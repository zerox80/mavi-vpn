import Architecture from '../components/Architecture';
import HandshakeSvg from '../components/HandshakeSvg';
import ZeroCopySvg from '../components/ZeroCopySvg';

export default function Technology() {
    return (
        <div className="animate-fade-in" style={{ paddingTop: 'calc(var(--spacing-xl) * 2)', paddingBottom: 'var(--spacing-xl)' }}>
            <div className="container" style={{ marginBottom: 'var(--spacing-xl)', textAlign: 'center' }}>
                <h1 className="section-title">Under the Hood</h1>
                <p className="section-subtitle" style={{ maxWidth: '800px', marginInline: 'auto' }}>
                    Explore the cryptographic and networking breakthroughs that allow Mavi VPN to
                    operate invisibly in hostile environments.
                </p>
            </div>

            <Architecture />

            <section className="container" style={{ marginTop: 'var(--spacing-xl)', marginBottom: 'var(--spacing-xl)' }}>
                <h2 className="section-title text-center" style={{ marginBottom: 'var(--spacing-lg)' }}>QUIC 0-RTT & ALPN Masquerading</h2>

                <div className="glass-panel" style={{ padding: 'var(--spacing-lg)', display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 'var(--spacing-lg)', alignItems: 'center' }}>
                    <div>
                        <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>Protocol Invisibility</h3>
                        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: '1rem' }}>
                            When CR (Censorship Resistance) Mode is enabled, Mavi VPN drops the standard <span style={{ fontFamily: 'monospace' }}>mavivpn</span> ALPN
                            identifier during the TLS 1.3 handshake. Instead, it masquerades as <span style={{ fontFamily: 'monospace' }}>h3</span> (HTTP/3).
                        </p>
                        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                            If an active DPI probe challenges the server with an invalid authentication token, the server
                            <strong> does not reset the connection</strong>. Instead, it serves a generic Nginx "200 OK" HTML page.
                            To any surveillance system, the VPN server is indistinguishable from a standard web server.
                        </p>
                    </div>

                    <div style={{ background: 'var(--bg-tertiary)', padding: 'var(--spacing-md)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-light)' }}>
                        <HandshakeSvg />
                    </div>
                </div>
            </section>

            <section className="container" style={{ marginBottom: 'var(--spacing-xl)' }}>
                <h2 className="section-title text-center" style={{ marginBottom: 'var(--spacing-lg)' }}>Zero-Copy Datapath in Rust</h2>
                <div className="glass-panel" style={{ padding: 'var(--spacing-lg)' }}>
                    <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: '1rem' }}>
                        Performance is driven by a multithreaded Tokio asynchronous runtime. Packets arriving on the Linux TUN interface
                        are read directly into memory buffers utilizing <span style={{ fontFamily: 'monospace' }}>bytes::BytesMut</span>.
                    </p>
                    <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: '2rem' }}>
                        These buffers are passed by reference counting through the encryption and encapsulation layers directly into the
                        QUIC stream. <strong>Zero payload cloning</strong> happens along the entire datapath, allowing the userspace
                        VPN to operate near the theoretical limits of the physical hardware.
                    </p>
                    <div style={{ background: 'var(--bg-tertiary)', padding: 'var(--spacing-sm)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-light)' }}>
                        <ZeroCopySvg />
                    </div>
                </div>
            </section>

        </div>
    );
}
