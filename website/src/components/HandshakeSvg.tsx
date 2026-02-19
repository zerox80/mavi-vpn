export default function HandshakeSvg() {
    return (
        <svg
            viewBox="0 0 800 400"
            className="w-full h-auto text-primary"
            style={{ fontFamily: 'Inter, sans-serif' }}
        >
            <defs>
                {/* Glow Effects */}
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="6" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <filter id="subtleGlow" x="-10%" y="-10%" width="120%" height="120%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>

                {/* Gradients */}
                <linearGradient id="clientGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--bg-primary)" />
                    <stop offset="100%" stopColor="var(--bg-secondary)" />
                </linearGradient>
                <linearGradient id="serverGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--bg-primary)" />
                    <stop offset="100%" stopColor="var(--bg-tertiary)" />
                </linearGradient>

                {/* Arrowhead */}
                <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--text-secondary)" />
                </marker>
                <marker id="arrowAccent" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent-base)" />
                </marker>
            </defs>

            {/* --- Background --- */}
            <rect width="800" height="400" fill="transparent" />

            {/* --- Entities --- */}
            {/* Client Node */}
            <g transform="translate(100, 50)">
                <rect width="140" height="60" rx="8" fill="url(#clientGrad)" stroke="var(--border-light)" strokeWidth="2" filter="url(#subtleGlow)" />
                <text x="70" y="32" textAnchor="middle" fill="var(--text-primary)" fontSize="16" fontWeight="700">Client</text>
                {/* Timeline Line */}
                <line x1="70" y1="60" x2="70" y2="350" stroke="var(--border-light)" strokeWidth="2" strokeDasharray="6 4" />
            </g>

            {/* Server Node */}
            <g transform="translate(560, 50)">
                <rect width="140" height="60" rx="8" fill="url(#serverGrad)" stroke="var(--accent-base)" strokeWidth="2" filter="url(#glow)" />
                <text x="70" y="32" textAnchor="middle" fill="var(--text-primary)" fontSize="16" fontWeight="700">Mavi Server</text>
                {/* Timeline Line */}
                <line x1="70" y1="60" x2="70" y2="350" stroke="var(--border-light)" strokeWidth="2" strokeDasharray="6 4" />
            </g>

            {/* --- Flow Arrows --- */}

            {/* Step 1: Initial Client Hello + ALPN */}
            <g transform="translate(170, 140)">
                <line x1="0" y1="0" x2="450" y2="20" stroke="var(--accent-base)" strokeWidth="2" markerEnd="url(#arrowAccent)" />
                <rect x="120" y="-20" width="220" height="26" rx="4" fill="var(--bg-primary)" stroke="var(--border-light)" />
                <text x="230" y="-3" textAnchor="middle" fill="var(--text-primary)" fontSize="13" fontWeight="600">TLS 1.3 ClientHello (0-RTT)</text>
                <text x="230" y="16" textAnchor="middle" fill="var(--text-secondary)" fontSize="11" fontFamily="monospace">ALPN: h3 (Masquerade)</text>
            </g>

            {/* Step 2: Auth Stream */}
            <g transform="translate(170, 200)">
                <line x1="0" y1="0" x2="450" y2="20" stroke="var(--text-secondary)" strokeWidth="2" markerEnd="url(#arrow)" />
                <rect x="150" y="-20" width="160" height="26" rx="4" fill="var(--bg-primary)" stroke="var(--border-light)" />
                <text x="230" y="-3" textAnchor="middle" fill="var(--text-primary)" fontSize="12" fontWeight="600">Auth Stream {`{ token }`}</text>
            </g>

            {/* Branching Logic (Valid vs Invalid) */}

            {/* Branch A: Invalid (CR Mode Defense) */}
            <path d="M 630 230 Q 720 230 720 260 Q 720 290 630 290" fill="none" stroke="var(--border-light)" strokeWidth="2" strokeDasharray="4 2" markerEnd="url(#arrow)" />
            <text x="760" y="255" textAnchor="middle" fill="var(--text-secondary)" fontSize="11" fontWeight="600">If invalid token / active probe:</text>
            <text x="760" y="270" textAnchor="middle" fill="var(--text-secondary)" fontSize="11">Return standard Nginx 200 OK</text>
            <text x="760" y="285" textAnchor="middle" fill="var(--text-secondary)" fontSize="11">Do NOT reset connection</text>

            {/* Branch B: Valid (VPN Payload) */}
            <g transform="translate(170, 310)">
                <line x1="450" y1="0" x2="0" y2="20" stroke="var(--accent-base)" strokeWidth="2" markerEnd="url(#arrowAccent)" />
                <rect x="80" y="-15" width="280" height="26" rx="4" fill="var(--bg-primary)" stroke="var(--accent-base)" filter="url(#subtleGlow)" />
                <text x="220" y="2" textAnchor="middle" fill="var(--text-primary)" fontSize="13" fontWeight="600">Encrypted TUN Payload (QUIC Datagram)</text>
            </g>

        </svg>
    );
}
