import { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Navbar() {
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            setScrolled(window.scrollY > 20);
        };
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    return (
        <header className={`navbar ${scrolled ? 'navbar-scrolled' : ''}`}>
            <div className="container navbar-container">
                <Link to="/" className="logo-group">
                    <div className="logo-icon-wrapper">
                        <Shield className="logo-icon" size={24} strokeWidth={2.5} />
                    </div>
                    <span className="logo-text">Mavi<span className="logo-accent">VPN</span></span>
                </Link>

                <nav className="nav-links">
                    <Link to="/" className="nav-link">Home</Link>
                    <Link to="/technology" className="nav-link">Technology</Link>
                    <a href="/#download" className="nav-link">Download</a>
                </nav>

                <div className="nav-actions">
                    <a href="#get-started" className="btn-primary btn-sm">Get Started</a>
                </div>
            </div>
        </header>
    );
}
