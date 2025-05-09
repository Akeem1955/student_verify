// Toast notification system
const ToastType = {
    SUCCESS: 'success',
    ERROR: 'error',
    INFO: 'info'
};

class ToastManager {
    constructor() {
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        document.body.appendChild(this.container);
    }

    show(message, type = ToastType.INFO, duration = 3000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = document.createElement('i');
        icon.className = this.getIconClass(type);
        
        const text = document.createElement('span');
        text.textContent = message;
        
        toast.appendChild(icon);
        toast.appendChild(text);
        this.container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    getIconClass(type) {
        switch (type) {
            case ToastType.SUCCESS:
                return 'fas fa-check-circle';
            case ToastType.ERROR:
                return 'fas fa-exclamation-circle';
            default:
                return 'fas fa-info-circle';
        }
    }
}

// Progress indicator system
class ProgressManager {
    constructor() {
        this.overlay = document.createElement('div');
        this.overlay.className = 'loading-overlay';
        this.overlay.style.display = 'none';
        
        this.content = document.createElement('div');
        this.content.className = 'loading-content';
        
        this.spinner = document.createElement('div');
        this.spinner.className = 'progress-spinner';
        
        this.text = document.createElement('div');
        this.text.className = 'progress-text';
        
        this.content.appendChild(this.spinner);
        this.content.appendChild(this.text);
        this.overlay.appendChild(this.content);
        document.body.appendChild(this.overlay);
    }

    show(message = 'Loading...') {
        this.text.textContent = message;
        this.overlay.style.display = 'flex';
    }

    hide() {
        this.overlay.style.display = 'none';
    }

    updateProgress(progress, message) {
        if (message) {
            this.text.textContent = message;
        }
    }
}

// Form validation system
class FormValidator {
    constructor(form) {
        this.form = form;
        this.errors = new Map();
        this.setupValidation();
    }

    setupValidation() {
        this.form.addEventListener('submit', (e) => {
            if (!this.validate()) {
                e.preventDefault();
            }
        });

        this.form.querySelectorAll('input, select, textarea').forEach(input => {
            input.addEventListener('blur', () => this.validateField(input));
            input.addEventListener('input', () => this.validateField(input));
        });
    }

    validateField(input) {
        const value = input.value.trim();
        let isValid = true;
        let errorMessage = '';

        // Required field validation
        if (input.hasAttribute('required') && !value) {
            isValid = false;
            errorMessage = 'This field is required';
        }

        // Email validation
        if (input.type === 'email' && value) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(value)) {
                isValid = false;
                errorMessage = 'Please enter a valid email address';
            }
        }

        // Password validation
        if (input.type === 'password' && value) {
            if (value.length < 8) {
                isValid = false;
                errorMessage = 'Password must be at least 8 characters long';
            }
        }

        // Update UI
        this.updateFieldValidation(input, isValid, errorMessage);
        return isValid;
    }

    updateFieldValidation(input, isValid, errorMessage) {
        const formGroup = input.closest('.form-group');
        if (!formGroup) return;

        const validationMessage = formGroup.querySelector('.validation-message') || 
            document.createElement('div');
        
        validationMessage.className = `validation-message ${isValid ? 'success' : 'error'}`;
        
        if (!isValid) {
            validationMessage.innerHTML = `
                <i class="fas fa-${isValid ? 'check' : 'exclamation'}-circle"></i>
                ${errorMessage}
            `;
            input.classList.add('error');
            input.classList.remove('success');
        } else {
            input.classList.remove('error');
            input.classList.add('success');
            validationMessage.innerHTML = `
                <i class="fas fa-check-circle"></i>
                Valid
            `;
        }

        if (!formGroup.querySelector('.validation-message')) {
            formGroup.appendChild(validationMessage);
        }
    }

    validate() {
        let isValid = true;
        this.form.querySelectorAll('input, select, textarea').forEach(input => {
            if (!this.validateField(input)) {
                isValid = false;
            }
        });
        return isValid;
    }
}

// Initialize UI utilities
const toastManager = new ToastManager();
const progressManager = new ProgressManager();

// Export utilities
window.UI = {
    toast: toastManager,
    progress: progressManager,
    FormValidator
}; 