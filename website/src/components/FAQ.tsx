import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

const faqs = [
    {
        question: "How does Mavi VPN bypass firewalls and DPI?",
        answer: "Mavi VPN utilizes an advanced Censorship Resistance (CR) Mode. Instead of broadcasting standard VPN signatures, the TLS 1.3 handshake drops the typical ALPN identifier and masquerades as standard HTTP/3 traffic. If an active probe queries the server, it responds with a generic Nginx 200 OK HTML page, making it fully indistinguishable from a standard web server."
    },
    {
        question: "Why use Rust instead of C or Go?",
        answer: "Rust provides absolute memory safety without needing a garbage collector. By building the Mavi VPN core in Rust, we completely eliminate entire classes of vulnerabilities (like buffer overflows) while achieving bare-metal performance through our zero-copy asynchronous datapath."
    },
    {
        question: "What is the Wintun adapter and why is it used?",
        answer: "Wintun is an extremely fast and stable virtual network adapter created by the WireGuard team. Instead of reinventing the wheel with a buggy driver, our Windows client leverages the Wintun driver directly, ensuring maximum compatibility, lowest latency, and rock-solid OS integration."
    },
    {
        question: "What is the 'Pinned MTU' strategy?",
        answer: "Many legacy VPNs fail on constrained networks (like DSL) because packets become too large and fragment. We solve this by strictly pinning the internal virtual network MTU to 1280 bytes, leaving exactly enough cryptographic headroom in the outer 1360 byte packet to guarantee seamless passage across any network globally."
    },
    {
        question: "Do you rely on Certificate Authorities (CAs)?",
        answer: "No. Traditional Certificate Authorities can be compromised or forced by state actors to issue rogue certificates. Mavi VPN relies purely on mathematical Certificate Pinning. The exact hash of the server's public key is known to the client in advance, rendering Man-in-the-Middle attacks mathematically impossible."
    }
];

export default function FAQ() {
    const [openIndex, setOpenIndex] = useState<number | null>(null);

    const toggleFaq = (index: number) => {
        setOpenIndex(openIndex === index ? null : index);
    };

    return (
        <section className="faq-section" id="faq" style={{ padding: 'var(--spacing-xl) 0', background: 'var(--bg-secondary)' }}>
            <div className="container">
                <div className="section-header text-center" style={{ marginBottom: 'var(--spacing-lg)' }}>
                    <h2 className="section-title">Frequently Asked Questions</h2>
                    <p className="section-subtitle" style={{ maxWidth: '600px', marginInline: 'auto' }}>
                        Everything you need to know about the deployment, operation, and security of Mavi VPN.
                    </p>
                </div>

                <div className="faq-container" style={{ maxWidth: '800px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {faqs.map((faq, index) => {
                        const isOpen = openIndex === index;
                        return (
                            <div
                                key={index}
                                className={`faq-item glass-panel ${isOpen ? 'open' : ''}`}
                                style={{
                                    borderRadius: 'var(--radius-md)',
                                    border: '1px solid var(--border-light)',
                                    overflow: 'hidden',
                                    transition: 'all 0.3s ease'
                                }}
                            >
                                <button
                                    className="faq-question"
                                    onClick={() => toggleFaq(index)}
                                    style={{
                                        width: '100%',
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center',
                                        padding: '1.25rem',
                                        background: 'none',
                                        border: 'none',
                                        color: 'var(--text-primary)',
                                        fontSize: '1.1rem',
                                        fontWeight: '600',
                                        cursor: 'pointer',
                                        textAlign: 'left'
                                    }}
                                >
                                    {faq.question}
                                    <ChevronDown
                                        size={20}
                                        className="text-secondary"
                                        style={{
                                            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                                            transition: 'transform 0.3s ease',
                                            flexShrink: 0,
                                            marginLeft: '1rem'
                                        }}
                                    />
                                </button>
                                <div
                                    className="faq-answer-wrapper"
                                    style={{
                                        maxHeight: isOpen ? '500px' : '0',
                                        overflow: 'hidden',
                                        transition: 'max-height 0.3s ease-in-out',
                                        background: 'var(--bg-primary)'
                                    }}
                                >
                                    <p
                                        className="faq-answer"
                                        style={{
                                            padding: '0 1.25rem 1.25rem',
                                            color: 'var(--text-secondary)',
                                            lineHeight: '1.6',
                                            margin: 0
                                        }}
                                    >
                                        {faq.answer}
                                    </p>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>
        </section>
    );
}
