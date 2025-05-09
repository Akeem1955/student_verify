// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Add animation on scroll
const observerOptions = {
    root: null,
    rootMargin: '0px',
    threshold: 0.1
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('fade-in');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

// Observe all sections
document.querySelectorAll('section').forEach(section => {
    section.classList.add('opacity-0');
    observer.observe(section);
});

// Add fade-in animation to CSS
const style = document.createElement('style');
style.textContent = `
    .opacity-0 {
        opacity: 0;
        transform: translateY(20px);
        transition: opacity 0.6s ease-out, transform 0.6s ease-out;
    }
    
    .fade-in {
        opacity: 1;
        transform: translateY(0);
    }
`;
document.head.appendChild(style);

// Mobile menu toggle (to be implemented)
const mobileMenuButton = document.createElement('button');
mobileMenuButton.className = 'mobile-menu-button';
mobileMenuButton.innerHTML = `
    <span></span>
    <span></span>
    <span></span>
`;
document.querySelector('.nav-container').appendChild(mobileMenuButton);

// Add mobile menu styles
const mobileStyles = document.createElement('style');
mobileStyles.textContent = `
    .mobile-menu-button {
        display: none;
        background: none;
        border: none;
        cursor: pointer;
        padding: 0.5rem;
    }
    
    .mobile-menu-button span {
        display: block;
        width: 25px;
        height: 3px;
        background: #2563eb;
        margin: 5px 0;
        transition: 0.3s;
    }
    
    @media (max-width: 768px) {
        .mobile-menu-button {
            display: block;
        }
        
        .nav-links {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            padding: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .nav-links.active {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
    }
`;
document.head.appendChild(mobileStyles);

// Mobile menu toggle functionality
mobileMenuButton.addEventListener('click', () => {
    const navLinks = document.querySelector('.nav-links');
    navLinks.classList.toggle('active');
});

const Landing = {
    elements: {
        getStartedBtn: null,
        studentBtn: null,
        clientBtn: null,
        navLinks: null
    },

    init() {
        // Initialize element references
        this.elements.getStartedBtn = document.querySelector('.nav-links .btn-primary');
        this.elements.studentBtn = document.querySelector('.cta-buttons .btn-primary');
        this.elements.clientBtn = document.querySelector('.cta-buttons .btn-secondary');
        this.elements.navLinks = document.querySelectorAll('.nav-links a[href^="#"]');

        // Set up event listeners
        this.setupEventListeners();
        this.setupSmoothScroll();
    },

    setupEventListeners() {
        // Note: Event listeners for direct navigation are no longer needed
        // since we're using <a> elements with href attributes
        // This method is kept for potential future additional event handling
        
        // If there are any remaining button elements, ensure they redirect properly
        const backupGetStartedBtn = document.querySelector('button.btn-primary');
        if (backupGetStartedBtn) {
            backupGetStartedBtn.addEventListener('click', () => {
                window.location.href = 'login.html';
            });
        }

        const backupStudentBtn = document.querySelector('button.cta-buttons .btn-primary');
        if (backupStudentBtn) {
            backupStudentBtn.addEventListener('click', () => {
                window.location.href = 'student-dashboard.html';
            });
        }

        const backupClientBtn = document.querySelector('button.cta-buttons .btn-secondary');
        if (backupClientBtn) {
            backupClientBtn.addEventListener('click', () => {
                window.location.href = 'client-dashboard.html';
            });
        }
    },

    setupSmoothScroll() {
        // Add smooth scrolling to nav links
        this.elements.navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                
                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    Landing.init();
}); 