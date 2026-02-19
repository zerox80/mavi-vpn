
import { EyeOff, Cpu, Globe2, Activity, Zap, ShieldCheck } from 'lucide-react';

const features = [
    {
        icon: <EyeOff className="text-accent" size={32} strokeWidth={1.5} />,
        title: 'Censorship Resistance (CR Mode)',
        description: 'Bypass strict firewalls (GFW, Corporate). Mavi VPN uses ALPN h3 (HTTP/3) masquerading to appear identically to standard web traffic, evading Deep Packet Inspection.',
    },
    {
        icon: <Globe2 className="text-accent" size={32} strokeWidth={1.5} />,
        title: 'The "Pinned MTU" Strategy',
        description: 'Solves the infamous "Packet Too Big" black holes on constrained DSL/PPPoE lines. We enforce a strict 1280 Byte inner payload and 1360 Byte outer tunnel, guaranteeing zero fragmentation.',
    },
    {
        icon: <Cpu className="text-accent" size={32} strokeWidth={1.5} />,
        title: 'Memory-Safe Rust Core',
        description: 'Engineered entirely in Rust for total memory safety and thread safety. Packets flow from the bare-metal TUN interface directly into the QUIC channel without memory cloning.',
    },
    {
        icon: <Zap className="text-accent" size={32} strokeWidth={1.5} />,
        title: 'Powered by Wintun',
        description: 'Our Windows client utilizes the battle-tested Wintun virtual network adapter from the WireGuard project, guaranteeing maximum throughput, lowest latency, and rock-solid OS integration.',
    },
    {
        icon: <Activity className="text-accent" size={32} strokeWidth={1.5} />,
        title: 'Cryptographic Independence',
        description: 'Eliminates reliance on easily compromised Certificate Authorities. Employs mathematically proven Certificate Pinning and pure TLS 1.3 (ChaCha20-Poly1305) over UDP.',
    },
    {
        icon: <ShieldCheck className="text-accent" size={32} strokeWidth={1.5} />,
        title: 'Transparent Infrastructure',
        description: 'No hidden trackers, no bloatware, and no opaque legacy protocols. The entire architecture is built for maximum speed and absolute privacy. What you see is what executes.',
    }
];

export default function Features() {
    return (
        <section className="features-section" id="features">
            <div className="container">

                <div className="section-header text-center">
                    <h2 className="section-title">Engineered for Hostile Networks.</h2>
                    <p className="section-subtitle">
                        Not just another wrapper around WireGuard. Mavi VPN is a ground-up QUIC implementation
                        designed to survive where legacy protocols are aggressively throttled or blocked.
                    </p>
                </div>

                <div className="features-grid">
                    {features.map((feature, index) => (
                        <div
                            key={index}
                            className="feature-card glass-panel"
                            style={{ animationDelay: `${index * 100}ms` }}
                        >
                            <div className="feature-icon-wrapper">
                                {feature.icon}
                            </div>
                            <h3 className="feature-title">{feature.title}</h3>
                            <p className="feature-description">{feature.description}</p>
                        </div>
                    ))}
                </div>

            </div>
        </section>
    );
}
