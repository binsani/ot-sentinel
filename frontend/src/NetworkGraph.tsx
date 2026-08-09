import cytoscape from 'cytoscape'
import { useEffect, useRef } from 'react'

import type { GraphData } from './types'

export function NetworkGraph({ data }: { data: GraphData }) {
  const container = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!container.current) return
    const graph = cytoscape({
      container: container.current,
      elements: [
        ...data.nodes.map((node) => ({ data: node })),
        ...data.edges.map((edge) => ({ data: edge })),
      ],
      layout: { name: 'cose', animate: false, fit: true, padding: 40 },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#34d399',
            'border-color': '#a7f3d0',
            'border-width': 1,
            color: '#d1fae5',
            label: 'data(label)',
            'font-family': 'ui-monospace, monospace',
            'font-size': 10,
            'text-margin-y': 8,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 'mapData(packet_count, 1, 1000, 1, 6)',
            'line-color': '#475569',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
          },
        },
      ],
    })
    return () => graph.destroy()
  }, [data])

  if (data.nodes.length === 0) {
    return <EmptyState text="No observed communication pairs yet." />
  }
  return <div ref={container} className="h-[560px] w-full" aria-label="Communication graph" />
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="grid h-[560px] place-items-center text-sm text-slate-500">
      <p>{text}</p>
    </div>
  )
}
