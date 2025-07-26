/**
 * Responsive Button Utilities for Rotaract Club Website
 * Handles button interactions, loading states, and responsive behavior
 */

class ResponsiveButtonManager {
    constructor() {
        this.init();
    }

    init() {
        this.setupButtonListeners();
        this.setupLoadingStates();
        this.setupResponsiveText();
        this.setupTouchOptimizations();
    }

    /**
     * Set up event listeners for all buttons
     */
    setupButtonListeners() {
        // Add click animation to all buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('btn') || e.target.closest('.btn')) {
                const button = e.target.classList.contains('btn') ? e.target : e.target.closest('.btn');
                this.addClickAnimation(button);
            }
        });

        // Handle form submissions with loading states
        document.addEventListener('submit', (e) => {
            const submitButton = e.target.querySelector('button[type="submit"]');
            if (submitButton) {
                this.setLoadingState(submitButton, true);
            }
        });
    }

    /**
     * Add click animation to button
     */
    addClickAnimation(button) {
        if (button.classList.contains('btn-animate')) {
            button.style.transform = 'translateY(0)';
            setTimeout(() => {
                button.style.transform = '';
            }, 150);
        }
    }

    /**
     * Set loading state for button
     */
    setLoadingState(button, isLoading) {
        if (isLoading) {
            button.classList.add('btn-loading');
            button.disabled = true;
            
            // Store original content
            if (!button.dataset.originalContent) {
                button.dataset.originalContent = button.innerHTML;
            }
            
            // Add loading spinner
            const spinner = '<i class="fas fa-spinner fa-spin me-2"></i>';
            const text = button.textContent.trim();
            button.innerHTML = spinner + 'Loading...';
        } else {
            button.classList.remove('btn-loading');
            button.disabled = false;
            
            // Restore original content
            if (button.dataset.originalContent) {
                button.innerHTML = button.dataset.originalContent;
            }
        }
    }

    /**
     * Setup responsive text handling
     */
    setupResponsiveText() {
        const handleResize = () => {
            const buttons = document.querySelectorAll('.btn-responsive-text');
            buttons.forEach(button => {
                const fullText = button.dataset.fullText;
                const shortText = button.dataset.shortText;
                
                if (fullText && shortText) {
                    if (window.innerWidth < 576) {
                        button.innerHTML = button.innerHTML.replace(fullText, shortText);
                    } else {
                        button.innerHTML = button.innerHTML.replace(shortText, fullText);
                    }
                }
            });
        };

        window.addEventListener('resize', handleResize);
        handleResize(); // Initial call
    }

    /**
     * Setup touch optimizations for mobile devices
     */
    setupTouchOptimizations() {
        // Add touch feedback for touch devices
        if ('ontouchstart' in window) {
            document.addEventListener('touchstart', (e) => {
                if (e.target.classList.contains('btn') || e.target.closest('.btn')) {
                    const button = e.target.classList.contains('btn') ? e.target : e.target.closest('.btn');
                    button.style.opacity = '0.8';
                }
            });

            document.addEventListener('touchend', (e) => {
                if (e.target.classList.contains('btn') || e.target.closest('.btn')) {
                    const button = e.target.classList.contains('btn') ? e.target : e.target.closest('.btn');
                    setTimeout(() => {
                        button.style.opacity = '';
                    }, 150);
                }
            });
        }
    }

    /**
     * Create a responsive button group
     */
    createResponsiveButtonGroup(buttons, container) {
        const buttonGroup = document.createElement('div');
        buttonGroup.className = 'btn-group-responsive';
        
        buttons.forEach(buttonConfig => {
            const button = this.createButton(buttonConfig);
            buttonGroup.appendChild(button);
        });
        
        if (container) {
            container.appendChild(buttonGroup);
        }
        
        return buttonGroup;
    }

    /**
     * Create a single button with responsive configuration
     */
    createButton(config) {
        const button = document.createElement(config.tag || 'button');
        button.type = config.type || 'button';
        button.className = this.buildButtonClasses(config);
        
        // Set content
        let content = '';
        if (config.icon) {
            content += `<i class="${config.icon} me-2"></i>`;
        }
        content += config.text || '';
        button.innerHTML = content;
        
        // Set attributes
        if (config.href) button.href = config.href;
        if (config.onclick) button.onclick = config.onclick;
        if (config.disabled) button.disabled = config.disabled;
        
        // Set data attributes for responsive text
        if (config.responsiveText) {
            button.dataset.fullText = config.text;
            button.dataset.shortText = config.responsiveText;
            button.classList.add('btn-responsive-text');
        }
        
        return button;
    }

    /**
     * Build button classes based on configuration
     */
    buildButtonClasses(config) {
        let classes = ['btn'];
        
        // Add variant classes
        if (config.variant) {
            classes.push(`btn-${config.variant}`);
        }
        
        // Add size classes
        if (config.size) {
            classes.push(`btn-${config.size}`);
        }
        
        // Add responsive classes
        if (config.responsive !== false) {
            classes.push('btn-animate');
        }
        
        // Add custom classes
        if (config.className) {
            classes.push(config.className);
        }
        
        // Add responsive width classes
        if (config.fullWidthMobile !== false) {
            classes.push('w-100', 'w-sm-auto');
        }
        
        return classes.join(' ');
    }

    /**
     * Handle button group stacking on mobile
     */
    handleButtonGroupStacking() {
        const buttonGroups = document.querySelectorAll('.btn-group');
        
        const checkStacking = () => {
            buttonGroups.forEach(group => {
                if (window.innerWidth < 576) {
                    group.classList.add('btn-group-mobile');
                } else {
                    group.classList.remove('btn-group-mobile');
                }
            });
        };
        
        window.addEventListener('resize', checkStacking);
        checkStacking(); // Initial call
    }

    /**
     * Add confirmation dialog to destructive buttons
     */
    addConfirmationDialogs() {
        const destructiveButtons = document.querySelectorAll('.btn-danger, .btn-outline-danger, [data-confirm]');
        
        destructiveButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const message = button.dataset.confirm || 'Are you sure you want to perform this action?';
                if (!confirm(message)) {
                    e.preventDefault();
                    e.stopPropagation();
                }
            });
        });
    }

    /**
     * Setup keyboard navigation for button groups
     */
    setupKeyboardNavigation() {
        document.addEventListener('keydown', (e) => {
            if (e.target.classList.contains('btn')) {
                const buttonGroup = e.target.closest('.btn-group, .btn-group-responsive');
                if (buttonGroup) {
                    const buttons = Array.from(buttonGroup.querySelectorAll('.btn'));
                    const currentIndex = buttons.indexOf(e.target);
                    
                    let nextIndex = currentIndex;
                    
                    switch (e.key) {
                        case 'ArrowRight':
                        case 'ArrowDown':
                            nextIndex = (currentIndex + 1) % buttons.length;
                            break;
                        case 'ArrowLeft':
                        case 'ArrowUp':
                            nextIndex = (currentIndex - 1 + buttons.length) % buttons.length;
                            break;
                        case 'Home':
                            nextIndex = 0;
                            break;
                        case 'End':
                            nextIndex = buttons.length - 1;
                            break;
                        default:
                            return;
                    }
                    
                    if (nextIndex !== currentIndex) {
                        e.preventDefault();
                        buttons[nextIndex].focus();
                    }
                }
            }
        });
    }
}

// Utility functions for global use
window.ButtonUtils = {
    /**
     * Show loading state on button
     */
    showLoading: function(buttonSelector) {
        const button = typeof buttonSelector === 'string' 
            ? document.querySelector(buttonSelector) 
            : buttonSelector;
        
        if (button && window.responsiveButtonManager) {
            window.responsiveButtonManager.setLoadingState(button, true);
        }
    },

    /**
     * Hide loading state on button
     */
    hideLoading: function(buttonSelector) {
        const button = typeof buttonSelector === 'string' 
            ? document.querySelector(buttonSelector) 
            : buttonSelector;
        
        if (button && window.responsiveButtonManager) {
            window.responsiveButtonManager.setLoadingState(button, false);
        }
    },

    /**
     * Create a responsive button
     */
    createButton: function(config) {
        if (window.responsiveButtonManager) {
            return window.responsiveButtonManager.createButton(config);
        }
        return null;
    },

    /**
     * Create a responsive button group
     */
    createButtonGroup: function(buttons, container) {
        if (window.responsiveButtonManager) {
            return window.responsiveButtonManager.createResponsiveButtonGroup(buttons, container);
        }
        return null;
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.responsiveButtonManager = new ResponsiveButtonManager();
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ResponsiveButtonManager;
}
