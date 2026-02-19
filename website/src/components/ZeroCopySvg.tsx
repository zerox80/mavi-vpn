export default function ZeroCopySvg() {
    return (
        <svg
            viewBox="0 0 800 300"
            className="w-full h-auto text-primary"
            style={{ fontFamily: 'Inter, sans-serif' }}
        >
            <defs>
                {/* Glow Effects */}
                <filter id="glowAccent" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="5" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>

                {/* Gradients */}
                <linearGradient id="kernelGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--bg-tertiary)" />
                    <stop offset="100%" stopColor="var(--border-light)" />
                </linearGradient>

                {/* Arrows */}
                <marker id="arrowSolid" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--text-secondary)" />
                </marker>
            </defs>

            {/* --- Background --- */}
            <rect width="800" height="300" fill="transparent" />

            {/* --- Zones --- */}
            {/* Kernel Space */}
            <rect x="50" y="200" width="700" height="80" rx="8" fill="url(#kernelGrad)" stroke="var(--border-light)" />
            <text x="400" y="245" textAnchor="middle" fill="var(--text-secondary)" fontSize="18" fontWeight="700" letterSpacing="2">KERNEL SPACE (Linux)</text>

            {/* Userspace */}
            <rect x="50" y="20" width="700" height="150" rx="8" fill="var(--bg-primary)" stroke="var(--border-light)" strokeDasharray="8 4" />
            <text x="400" y="45" textAnchor="middle" fill="var(--text-primary)" fontSize="18" fontWeight="700" letterSpacing="2">USERSPACE (Mavi VPN Core)</text>

            {/* --- Elements --- */}

            {/* TUN Interface */}
            <g transform="translate(100, 160)">
                <rect width="120" height="80" rx="6" fill="var(--bg-secondary)" stroke="var(--text-tertiary)" strokeWidth="2" />
                <text x="60" y="45" textAnchor="middle" fill="var(--text-primary)" fontSize="14" fontWeight="600">TUN Intf</text>
            </g>

            {/* Rust Buffer (BytesMut) */}
            <g transform="translate(340, 70)">
                <rect width="140" height="60" rx="6" fill="var(--bg-secondary)" stroke="var(--accent-base)" strokeWidth="2" filter="url(#glowAccent)" />
                <text x="70" y="25" textAnchor="middle" fill="var(--text-primary)" fontSize="14" fontWeight="700">Memory Buffer</text>
                <text x="70" y="42" textAnchor="middle" fill="var(--accent-base)" fontSize="12" fontFamily="monospace">bytes::BytesMut</text>
            </g>

            {/* QUIC Socket */}
            <g transform="translate(580, 160)">
                <rect width="120" height="80" rx="6" fill="var(--bg-secondary)" stroke="var(--text-tertiary)" strokeWidth="2" />
                <text x="60" y="45" textAnchor="middle" fill="var(--text-primary)" fontSize="14" fontWeight="600">UDP Socket</text>
            </g>

            {/* --- Data Flow (Zero Copy) --- */}

            {/* Read from TUN */}
            <path d="M 160 160 Q 160 100 340 100" fill="none" stroke="var(--text-secondary)" strokeWidth="3" markerEnd="url(#arrowSolid)" />
            <text x="210" y="90" fill="var(--text-secondary)" fontSize="12" fontWeight="600">1. Direct Read</text>

            {/* Encrypt/Wrap (In Place) */}
            <path d="M 410 70 A 30 30 0 1 1 450 70" fill="none" stroke="var(--accent-base)" strokeWidth="2" strokeDasharray="4 2" markerEnd="url(#arrowSolid)" />
            <text x="480" y="55" fill="var(--accent-base)" fontSize="11" fontWeight="600">2. TLS/QUIC Encap</text>
            <text x="480" y="68" fill="var(--accent-base)" fontSize="10">(No cloning)</text>

            {/* Write to UDP */}
            <path d="M 480 100 Q 640 100 640 160" fill="none" stroke="var(--text-secondary)" strokeWidth="3" markerEnd="url(#arrowSolid)" />
            <text x="560" y="90" fill="var(--text-secondary)" fontSize="12" fontWeight="600">3. Direct Write</text>

        </svg>
    );
}
