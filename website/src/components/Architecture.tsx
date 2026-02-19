


export default function Architecture() {
    return (
        <section className="architecture-section" id="architecture">
            <div className="container">

                <div className="architecture-grid">

                    <div className="architecture-content">
                        <h2 className="section-title">The "Pinned MTU" Paradigm.</h2>
                        <p className="architecture-description">
                            Most residential connections (DS-Lite, PPPoE) suffer from maximum transmission unit (MTU) limitations. Standard VPNs relying on 1500-byte packets inevitably cause fragmentation. Modern firewalls abhor fragments, silently dropping them into "Black Holes".
                        </p>
                        <p className="architecture-description">
                            By enforcing a mathematically precise dual-layer MTU system—a 1280 Byte inner payload wrapped strictly in a 1360 Byte outer tunnel—Mavi VPN bypasses Path MTU Discovery failures completely. This absolute limit guarantees zero fragmentation while leaving 38 bytes for the QUIC/UDP/TLS overhead.
                        </p>

                        <div className="arch-stats">
                            <div className="stat-item">
                                <div className="stat-value text-accent">1360<span>B</span></div>
                                <div className="stat-label">Outer QUIC Wire</div>
                            </div>
                            <div className="stat-item">
                                <div className="stat-value text-accent">1280<span>B</span></div>
                                <div className="stat-label">Inner Payload</div>
                            </div>
                            <div className="stat-item">
                                <div className="stat-value text-accent">0<span>%</span></div>
                                <div className="stat-label">Fragmentation Risk</div>
                            </div>
                        </div>
                    </div>

                    <div className="architecture-visual">
                        <div className="diagram-container glass-panel">
                            <div className="diagram-layer outer-layer">
                                <span className="layer-label">Wire Layer (Quinn) 1360B</span>
                                <div className="diagram-layer inner-layer">
                                    <span className="layer-label text-accent">Payload (TUN) 1280B</span>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>

            </div>
        </section>
    );
}
