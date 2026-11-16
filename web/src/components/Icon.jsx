const paths = {
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  folder: 'M3 5h6l2 2h10v13H3z',
  folderOpen: 'M3 10V5h6l2 2h9v3 M3 10h19l-3 10H3z',
  model: 'm12 2 9 5v10l-9 5-9-5V7z M3 7l9 5 9-5 M12 12v10 M7.5 4.5l9 5',
  document: 'M7 3h8l4 4v14H5V3h2 M14 3v5h5 M8 12h8 M8 16h8',
  tasks: 'M9 5h12v15H3V5h2 M7 3h10v4H7z M6 12l2 2 4-4 M14 12h4 M6 17h12',
  chat: 'M4 3h16v14H9l-5 4z M8 7h8 M8 11h5',
  team: 'M16 21v-3a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v3 M9 10a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M17 3a4 4 0 0 1 0 8 M22 21v-3a4 4 0 0 0-3-4',
  settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2',
  left: 'm14 5-7 7 7 7', right: 'm9 5 7 7-7 7', down: 'm5 9 7 7 7-7',
  plus: 'M12 5v14 M5 12h14', minus: 'M5 12h14', close: 'm6 6 12 12 M18 6 6 18',
  search: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6',
  download: 'M12 3v12 M7 10l5 5 5-5 M4 16v5h16v-5',
  history: 'M3 11a9 9 0 1 1 3 8 M3 4v7h7 M12 7v5l3 2',
  menu: 'M3 6h18 M3 12h18 M3 18h18',
  logout: 'M10 4H4v16h6 M9 12h12 M16 7l5 5-5 5',
  refresh: 'M20 8a8 8 0 1 0 0 8 M20 3v5h-5',
}
export default function Icon({ name, size = 20, ...props }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}><path d={paths[name] || paths.document} /></svg>
}
