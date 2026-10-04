export function UserAvatar({ name, image, className = '' }: { name: string; image?: string | null; className?: string }) {
  if (image) return <span className={`avatar ${className}`}><img src={image} alt={`${name} profile`}/></span>;
  const initials = name.split(' ').filter(Boolean).map(part => part[0]).slice(0, 2).join('').toUpperCase();
  return <span className={`avatar ${className}`}>{initials || '?'}</span>;
}
