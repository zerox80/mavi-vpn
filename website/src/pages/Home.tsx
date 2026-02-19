import Hero from '../components/Hero';
import Features from '../components/Features';
import FAQ from '../components/FAQ';

export default function Home() {
    return (
        <div className="animate-fade-in">
            <Hero />
            <Features />
            {/* Short teaser for Technology page below features */}
            <section className="container text-center" style={{ paddingBottom: 'var(--spacing-xl)' }}>
                <h3 className="section-title" style={{ fontSize: '1.5rem', marginBottom: '1rem' }}>Want to look under the hood?</h3>
                <p className="section-subtitle" style={{ marginBottom: '1.5rem', maxWidth: '600px', marginInline: 'auto' }}>
                    Discover how our Pinned MTU engine and QUIC Zero-Copy datapath achieve high-speed censorship resistance.
                </p>
                <a href="/technology" className="btn-secondary">
                    Read Technical Deep Dive
                </a>
            </section>
            <FAQ />
        </div>
    );
}
