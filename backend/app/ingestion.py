import hmac
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.alerting import enqueue_alert
from app.audit import append_audit_log
from app.config import get_settings
from app.database import get_session
from app.models import Asset, Observation, ProtocolEvent
from app.schemas import (
    Dnp3ObservationIn,
    Iec61850ObservationIn,
    IngestResult,
    ModbusObservationIn,
    OpcUaObservationIn,
    S7ObservationIn,
)

router = APIRouter(prefix="/api/v1/ingest", tags=["sensor ingestion"])


def existing_ingest_result(session: Session, event_id: object | None) -> IngestResult | None:
    """Serialize retries for one sensor event and return its original result."""
    if event_id is None:
        return None
    event_key = str(event_id)
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:event_key, 0))"),
        {"event_key": event_key},
    )
    observation = session.scalar(
        select(Observation).where(Observation.sensor_event_id == event_id)
    )
    if observation is None:
        return None
    protocol_event = session.scalar(
        select(ProtocolEvent).where(ProtocolEvent.observation_id == observation.id)
    )
    if protocol_event is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="sensor event exists without a protocol event",
        )
    session.commit()
    return IngestResult(
        asset_id=str(observation.asset_id),
        observation_id=observation.id,
        protocol_event_id=protocol_event.id,
        created_asset=False,
    )


def authenticate_sensor(x_sensor_key: str = Header()) -> None:
    expected = get_settings().sensor_ingest_api_key.get_secret_value()
    if not hmac.compare_digest(x_sensor_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid sensor key")


@router.post(
    "/modbus",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(authenticate_sensor)],
)
def ingest_modbus(
    data: ModbusObservationIn,
    session: Session = Depends(get_session),
) -> IngestResult:
    if existing := existing_ingest_result(session, data.event_id):
        return existing
    server_is_destination = data.destination_port == 502
    asset_ip = data.destination_ip if server_is_destination else data.source_ip
    asset_mac = data.destination_mac if server_is_destination else data.source_mac

    # Prevent two sensors creating the same site/IP asset concurrently.
    lock_key = f"{data.site_id}:{asset_ip}"
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": lock_key},
    )
    asset = session.scalar(
        select(Asset)
        .where(Asset.site_id == data.site_id, Asset.ip_address == str(asset_ip))
        .with_for_update()
    )
    created_asset = asset is None
    if asset is None:
        asset = Asset(
            site_id=data.site_id,
            ip_address=str(asset_ip),
            mac_address=asset_mac,
            protocols=["modbus_tcp"],
            fingerprint={"modbus_unit_ids": [data.unit_id]},
            first_seen=data.observed_at,
            last_seen=data.observed_at,
        )
        session.add(asset)
        session.flush()
    else:
        asset.first_seen = min(asset.first_seen, data.observed_at)
        asset.last_seen = max(asset.last_seen, data.observed_at)
        if "modbus_tcp" not in asset.protocols:
            asset.protocols = [*asset.protocols, "modbus_tcp"]
        unit_ids = list(asset.fingerprint.get("modbus_unit_ids", []))
        if data.unit_id not in unit_ids:
            unit_ids.append(data.unit_id)
            asset.fingerprint = {**asset.fingerprint, "modbus_unit_ids": sorted(unit_ids)}
        if asset.mac_address is None and asset_mac is not None:
            asset.mac_address = asset_mac

    identification = data.fields.get("device_identification")
    if server_is_destination is False and isinstance(identification, dict):
        vendor = identification.get("vendor_name")
        model = (
            identification.get("model_name")
            or identification.get("product_name")
            or identification.get("product_code")
        )
        revision = identification.get("revision")
        if isinstance(vendor, str) and vendor:
            asset.vendor = vendor[:255]
        if isinstance(model, str) and model:
            asset.model = model[:255]
        if isinstance(revision, str) and revision:
            _apply_firmware_version(
                session,
                asset,
                revision[:255],
                data.observed_at,
                data.sensor_id,
            )

    observation = Observation(
        sensor_event_id=data.event_id,
        asset_id=asset.id,
        sensor_id=data.sensor_id,
        observed_at=data.observed_at,
        source_ip=str(data.source_ip),
        destination_ip=str(data.destination_ip),
        source_port=data.source_port,
        destination_port=data.destination_port,
        protocol="modbus_tcp",
        packet_count=1,
        byte_count=data.byte_count,
        metadata_={"transaction_id": data.transaction_id, "unit_id": data.unit_id},
    )
    session.add(observation)
    session.flush()
    event = ProtocolEvent(
        asset_id=asset.id,
        observation_id=observation.id,
        protocol="modbus_tcp",
        event_type="exception" if data.is_exception else "message",
        occurred_at=data.observed_at,
        fields={"function_code": data.function_code, **data.fields},
        payload_digest=bytes.fromhex(data.payload_sha256),
    )
    session.add(event)
    session.flush()
    append_audit_log(
        session,
        action="asset.discovered" if created_asset else "asset.observed",
        object_type="asset",
        object_id=str(asset.id),
        details={"sensor_id": data.sensor_id, "protocol": "modbus_tcp"},
        actor_subject=f"sensor:{data.sensor_id}",
    )
    session.commit()
    return IngestResult(
        asset_id=str(asset.id),
        observation_id=observation.id,
        protocol_event_id=event.id,
        created_asset=created_asset,
    )


@router.post(
    "/iec61850",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(authenticate_sensor)],
)
def ingest_iec61850(
    data: Iec61850ObservationIn,
    session: Session = Depends(get_session),
) -> IngestResult:
    if existing := existing_ingest_result(session, data.event_id):
        return existing
    server_is_source = data.source_port == 102
    asset_ip = data.source_ip if server_is_source else data.destination_ip
    asset_mac = data.source_mac if server_is_source else data.destination_mac
    lock_key = f"{data.site_id}:{asset_ip}"
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": lock_key},
    )
    asset = session.scalar(
        select(Asset)
        .where(Asset.site_id == data.site_id, Asset.ip_address == str(asset_ip))
        .with_for_update()
    )
    created_asset = asset is None
    if asset is None:
        asset = Asset(
            site_id=data.site_id,
            ip_address=str(asset_ip),
            mac_address=asset_mac,
            protocols=["iec61850_mms"],
            fingerprint={},
            first_seen=data.observed_at,
            last_seen=data.observed_at,
        )
        session.add(asset)
        session.flush()
    else:
        asset.first_seen = min(asset.first_seen, data.observed_at)
        asset.last_seen = max(asset.last_seen, data.observed_at)
        if "iec61850_mms" not in asset.protocols:
            asset.protocols = [*asset.protocols, "iec61850_mms"]
        if asset.mac_address is None and asset_mac is not None:
            asset.mac_address = asset_mac
    fingerprint = dict(asset.fingerprint)
    pdu_types = set(fingerprint.get("iec61850_mms_pdu_types", []))
    pdu_types.add(data.mms_pdu_type)
    fingerprint["iec61850_mms_pdu_types"] = sorted(pdu_types)
    references = set(fingerprint.get("iec61850_object_references", []))
    references.update(data.object_references)
    fingerprint["iec61850_object_references"] = sorted(references)[:256]
    asset.fingerprint = fingerprint

    observation = Observation(
        sensor_event_id=data.event_id,
        asset_id=asset.id,
        sensor_id=data.sensor_id,
        observed_at=data.observed_at,
        source_ip=str(data.source_ip),
        destination_ip=str(data.destination_ip),
        source_port=data.source_port,
        destination_port=data.destination_port,
        protocol="iec61850_mms",
        packet_count=1,
        byte_count=data.byte_count,
        metadata_={"cotp_type": data.cotp_type, "mms_pdu_type": data.mms_pdu_type},
    )
    session.add(observation)
    session.flush()
    event = ProtocolEvent(
        asset_id=asset.id,
        observation_id=observation.id,
        protocol="iec61850_mms",
        event_type=data.mms_pdu_type,
        occurred_at=data.observed_at,
        fields={
            "invoke_id": data.invoke_id,
            "service_tag": data.service_tag,
            "object_references": data.object_references,
            **data.fields,
        },
        payload_digest=bytes.fromhex(data.payload_sha256),
    )
    session.add(event)
    session.flush()
    append_audit_log(
        session,
        action="asset.discovered" if created_asset else "asset.observed",
        object_type="asset",
        object_id=str(asset.id),
        details={"sensor_id": data.sensor_id, "protocol": "iec61850_mms"},
        actor_subject=f"sensor:{data.sensor_id}",
    )
    session.commit()
    return IngestResult(
        asset_id=str(asset.id),
        observation_id=observation.id,
        protocol_event_id=event.id,
        created_asset=created_asset,
    )


def _apply_firmware_version(
    session: Session,
    asset: Asset,
    version: str,
    observed_at: Any,
    sensor_id: str,
) -> None:
    previous = asset.firmware_version
    was_drifted = asset.firmware_drift_detected_at is not None
    asset.firmware_version = version
    is_drifted = bool(asset.firmware_baseline and version != asset.firmware_baseline)
    if is_drifted and not was_drifted:
        asset.firmware_drift_detected_at = observed_at
        enqueue_alert(
            session,
            event_type="firmware_drift",
            site_id=asset.site_id,
            payload={
                "asset_id": str(asset.id),
                "ip_address": str(asset.ip_address),
                "baseline": asset.firmware_baseline,
                "observed": version,
            },
        )
        append_audit_log(
            session,
            action="firmware.drift_detected",
            object_type="asset",
            object_id=str(asset.id),
            details={
                "baseline": asset.firmware_baseline,
                "previous": previous,
                "observed": version,
            },
            actor_subject=f"sensor:{sensor_id}",
        )
    elif not is_drifted and was_drifted:
        asset.firmware_drift_detected_at = None
        append_audit_log(
            session,
            action="firmware.drift_resolved",
            object_type="asset",
            object_id=str(asset.id),
            details={
                "baseline": asset.firmware_baseline,
                "previous": previous,
                "observed": version,
            },
            actor_subject=f"sensor:{sensor_id}",
        )


@router.post(
    "/dnp3",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(authenticate_sensor)],
)
def ingest_dnp3(
    data: Dnp3ObservationIn,
    session: Session = Depends(get_session),
) -> IngestResult:
    if existing := existing_ingest_result(session, data.event_id):
        return existing
    outstation_is_source = not data.direction_from_master
    asset_ip = data.source_ip if outstation_is_source else data.destination_ip
    asset_mac = data.source_mac if outstation_is_source else data.destination_mac
    outstation_address = (
        data.link_source_address if outstation_is_source else data.link_destination_address
    )
    lock_key = f"{data.site_id}:{asset_ip}"
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": lock_key},
    )
    asset = session.scalar(
        select(Asset)
        .where(Asset.site_id == data.site_id, Asset.ip_address == str(asset_ip))
        .with_for_update()
    )
    created_asset = asset is None
    if asset is None:
        asset = Asset(
            site_id=data.site_id,
            ip_address=str(asset_ip),
            mac_address=asset_mac,
            protocols=["dnp3"],
            fingerprint={"dnp3_outstation_addresses": [outstation_address]},
            first_seen=data.observed_at,
            last_seen=data.observed_at,
        )
        session.add(asset)
        session.flush()
    else:
        asset.first_seen = min(asset.first_seen, data.observed_at)
        asset.last_seen = max(asset.last_seen, data.observed_at)
        if "dnp3" not in asset.protocols:
            asset.protocols = [*asset.protocols, "dnp3"]
        addresses = list(asset.fingerprint.get("dnp3_outstation_addresses", []))
        if outstation_address not in addresses:
            addresses.append(outstation_address)
            asset.fingerprint = {
                **asset.fingerprint,
                "dnp3_outstation_addresses": sorted(addresses),
            }
        if asset.mac_address is None and asset_mac is not None:
            asset.mac_address = asset_mac

    observation = Observation(
        sensor_event_id=data.event_id,
        asset_id=asset.id,
        sensor_id=data.sensor_id,
        observed_at=data.observed_at,
        source_ip=str(data.source_ip),
        destination_ip=str(data.destination_ip),
        source_port=data.source_port,
        destination_port=data.destination_port,
        protocol="dnp3",
        packet_count=1,
        byte_count=data.byte_count,
        metadata_={
            "link_source_address": data.link_source_address,
            "link_destination_address": data.link_destination_address,
        },
    )
    session.add(observation)
    session.flush()
    event = ProtocolEvent(
        asset_id=asset.id,
        observation_id=observation.id,
        protocol="dnp3",
        event_type=data.application_function_name or "link_frame",
        occurred_at=data.observed_at,
        fields={
            "link_function": data.link_function,
            "transport_sequence": data.transport_sequence,
            "application_function": data.application_function,
            "application_sequence": data.application_sequence,
            "internal_indications": data.internal_indications,
            **data.fields,
        },
        payload_digest=bytes.fromhex(data.payload_sha256),
    )
    session.add(event)
    session.flush()
    append_audit_log(
        session,
        action="asset.discovered" if created_asset else "asset.observed",
        object_type="asset",
        object_id=str(asset.id),
        details={"sensor_id": data.sensor_id, "protocol": "dnp3"},
        actor_subject=f"sensor:{data.sensor_id}",
    )
    session.commit()
    return IngestResult(
        asset_id=str(asset.id),
        observation_id=observation.id,
        protocol_event_id=event.id,
        created_asset=created_asset,
    )


@router.post(
    "/s7comm",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(authenticate_sensor)],
)
def ingest_s7comm(
    data: S7ObservationIn,
    session: Session = Depends(get_session),
) -> IngestResult:
    if existing := existing_ingest_result(session, data.event_id):
        return existing
    server_is_source = data.source_port == 102
    asset_ip = data.source_ip if server_is_source else data.destination_ip
    asset_mac = data.source_mac if server_is_source else data.destination_mac
    lock_key = f"{data.site_id}:{asset_ip}"
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": lock_key},
    )
    asset = session.scalar(
        select(Asset)
        .where(Asset.site_id == data.site_id, Asset.ip_address == str(asset_ip))
        .with_for_update()
    )
    created_asset = asset is None
    evidence: dict[str, Any] = {}
    if data.rack is not None and data.slot is not None:
        evidence["s7_rack_slots"] = [{"rack": data.rack, "slot": data.slot}]
    negotiated = data.fields.get("negotiated_pdu_length")
    if isinstance(negotiated, int):
        evidence["s7_negotiated_pdu_lengths"] = [negotiated]
    if asset is None:
        asset = Asset(
            site_id=data.site_id,
            ip_address=str(asset_ip),
            mac_address=asset_mac,
            protocols=["s7comm"],
            fingerprint=evidence,
            first_seen=data.observed_at,
            last_seen=data.observed_at,
        )
        session.add(asset)
        session.flush()
    else:
        asset.first_seen = min(asset.first_seen, data.observed_at)
        asset.last_seen = max(asset.last_seen, data.observed_at)
        if "s7comm" not in asset.protocols:
            asset.protocols = [*asset.protocols, "s7comm"]
        fingerprint = dict(asset.fingerprint)
        if "s7_rack_slots" in evidence:
            rack_slots = list(fingerprint.get("s7_rack_slots", []))
            for rack_slot in evidence["s7_rack_slots"]:
                if rack_slot not in rack_slots:
                    rack_slots.append(rack_slot)
            fingerprint["s7_rack_slots"] = rack_slots
        if "s7_negotiated_pdu_lengths" in evidence:
            sizes = list(fingerprint.get("s7_negotiated_pdu_lengths", []))
            if negotiated not in sizes:
                sizes.append(negotiated)
            fingerprint["s7_negotiated_pdu_lengths"] = sorted(sizes)
        asset.fingerprint = fingerprint
        if asset.mac_address is None and asset_mac is not None:
            asset.mac_address = asset_mac

    observation = Observation(
        sensor_event_id=data.event_id,
        asset_id=asset.id,
        sensor_id=data.sensor_id,
        observed_at=data.observed_at,
        source_ip=str(data.source_ip),
        destination_ip=str(data.destination_ip),
        source_port=data.source_port,
        destination_port=data.destination_port,
        protocol="s7comm",
        packet_count=1,
        byte_count=data.byte_count,
        metadata_={
            "cotp_type": data.cotp_type,
            "source_tsap": data.source_tsap,
            "destination_tsap": data.destination_tsap,
        },
    )
    session.add(observation)
    session.flush()
    event = ProtocolEvent(
        asset_id=asset.id,
        observation_id=observation.id,
        protocol="s7comm",
        event_type=data.function_name or data.cotp_type,
        occurred_at=data.observed_at,
        fields={
            "pdu_reference": data.pdu_reference,
            "rosctr": data.rosctr,
            "rosctr_name": data.rosctr_name,
            "function_code": data.function_code,
            "error_class": data.error_class,
            "error_code": data.error_code,
            **data.fields,
        },
        payload_digest=bytes.fromhex(data.payload_sha256),
    )
    session.add(event)
    session.flush()
    append_audit_log(
        session,
        action="asset.discovered" if created_asset else "asset.observed",
        object_type="asset",
        object_id=str(asset.id),
        details={"sensor_id": data.sensor_id, "protocol": "s7comm"},
        actor_subject=f"sensor:{data.sensor_id}",
    )
    session.commit()
    return IngestResult(
        asset_id=str(asset.id),
        observation_id=observation.id,
        protocol_event_id=event.id,
        created_asset=created_asset,
    )


@router.post(
    "/opcua",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(authenticate_sensor)],
)
def ingest_opcua(
    data: OpcUaObservationIn,
    session: Session = Depends(get_session),
) -> IngestResult:
    if existing := existing_ingest_result(session, data.event_id):
        return existing
    server_is_source = data.source_port == 4840
    asset_ip = data.source_ip if server_is_source else data.destination_ip
    asset_mac = data.source_mac if server_is_source else data.destination_mac
    lock_key = f"{data.site_id}:{asset_ip}"
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
        {"lock_key": lock_key},
    )
    asset = session.scalar(
        select(Asset)
        .where(Asset.site_id == data.site_id, Asset.ip_address == str(asset_ip))
        .with_for_update()
    )
    created_asset = asset is None
    if asset is None:
        asset = Asset(
            site_id=data.site_id,
            ip_address=str(asset_ip),
            mac_address=asset_mac,
            protocols=["opcua"],
            fingerprint={},
            first_seen=data.observed_at,
            last_seen=data.observed_at,
        )
        session.add(asset)
        session.flush()
    else:
        asset.first_seen = min(asset.first_seen, data.observed_at)
        asset.last_seen = max(asset.last_seen, data.observed_at)
        if "opcua" not in asset.protocols:
            asset.protocols = [*asset.protocols, "opcua"]
        if asset.mac_address is None and asset_mac is not None:
            asset.mac_address = asset_mac
    fingerprint = dict(asset.fingerprint)
    if data.endpoint_url:
        endpoints = list(fingerprint.get("opcua_endpoint_urls", []))
        if data.endpoint_url not in endpoints:
            endpoints.append(data.endpoint_url)
        fingerprint["opcua_endpoint_urls"] = sorted(endpoints)
    if data.security_policy_uri:
        policies = list(fingerprint.get("opcua_security_policies", []))
        if data.security_policy_uri not in policies:
            policies.append(data.security_policy_uri)
        fingerprint["opcua_security_policies"] = sorted(policies)
    for field_name in ("receive_buffer_size", "send_buffer_size", "max_message_size"):
        value = data.fields.get(field_name)
        if isinstance(value, int):
            fingerprint[f"opcua_{field_name}"] = value
    asset.fingerprint = fingerprint

    observation = Observation(
        sensor_event_id=data.event_id,
        asset_id=asset.id,
        sensor_id=data.sensor_id,
        observed_at=data.observed_at,
        source_ip=str(data.source_ip),
        destination_ip=str(data.destination_ip),
        source_port=data.source_port,
        destination_port=data.destination_port,
        protocol="opcua",
        packet_count=1,
        byte_count=data.byte_count,
        metadata_={
            "message_type": data.message_type,
            "chunk_type": data.chunk_type,
            "secure_channel_id": data.secure_channel_id,
        },
    )
    session.add(observation)
    session.flush()
    event = ProtocolEvent(
        asset_id=asset.id,
        observation_id=observation.id,
        protocol="opcua",
        event_type=data.service_name or data.message_type.lower(),
        occurred_at=data.observed_at,
        fields={
            "security_policy_uri": data.security_policy_uri,
            "token_id": data.token_id,
            "sequence_number": data.sequence_number,
            "request_id": data.request_id,
            "service_node_id": data.service_node_id,
            **data.fields,
        },
        payload_digest=bytes.fromhex(data.payload_sha256),
    )
    session.add(event)
    session.flush()
    append_audit_log(
        session,
        action="asset.discovered" if created_asset else "asset.observed",
        object_type="asset",
        object_id=str(asset.id),
        details={"sensor_id": data.sensor_id, "protocol": "opcua"},
        actor_subject=f"sensor:{data.sensor_id}",
    )
    session.commit()
    return IngestResult(
        asset_id=str(asset.id),
        observation_id=observation.id,
        protocol_event_id=event.id,
        created_asset=created_asset,
    )
