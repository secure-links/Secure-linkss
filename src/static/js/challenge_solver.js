/**
 * Advanced Client-Side Challenge Solver
 * Handles various browser verification challenges
 */

class ChallengeSolver {
    constructor() {
        this.results = {};
        this.startTime = Date.now();
        this.mouseEvents = [];
        this.totalMouseDistance = 0;
        this.lastMousePosition = { x: 0, y: 0 };
        
        // Initialize mouse tracking
        this.initializeMouseTracking();
    }
    
    initializeMouseTracking() {
        document.addEventListener('mousemove', (event) => {
            const currentPos = { x: event.clientX, y: event.clientY };
            
            if (this.lastMousePosition.x !== 0 || this.lastMousePosition.y !== 0) {
                const distance = Math.sqrt(
                    Math.pow(currentPos.x - this.lastMousePosition.x, 2) +
                    Math.pow(currentPos.y - this.lastMousePosition.y, 2)
                );
                this.totalMouseDistance += distance;
            }
            
            this.mouseEvents.push({
                x: currentPos.x,
                y: currentPos.y,
                timestamp: Date.now()
            });
            
            this.lastMousePosition = currentPos;
            
            // Keep only recent events
            if (this.mouseEvents.length > 100) {
                this.mouseEvents = this.mouseEvents.slice(-50);
            }
        });
    }
    
    async solveChallenge(challengeData) {
        console.log('Solving challenge:', challengeData.challenge_id);
        
        const components = challengeData.components;
        
        // Solve each challenge component
        if (components.canvas_challenge) {
            this.results.canvas_result = await this.solveCanvasChallenge(components.canvas_challenge);
        }
        
        if (components.timing_challenge) {
            this.results.timing_result = await this.solveTimingChallenge(components.timing_challenge);
        }
        
        if (components.proof_of_work) {
            this.results.pow_result = await this.solveProofOfWork(components.proof_of_work);
        }
        
        if (components.fingerprint_challenge) {
            this.results.fingerprint_result = await this.solveFingerprintChallenge(components.fingerprint_challenge);
        }
        
        if (components.math_challenge) {
            this.results.math_result = await this.solveMathChallenge(components.math_challenge);
        }
        
        if (components.memory_challenge) {
            this.results.memory_result = await this.solveMemoryChallenge(components.memory_challenge);
        }
        
        // Add interaction data
        this.results.interaction_result = {
            mouse_events: this.mouseEvents.slice(-20), // Last 20 events
            total_distance: this.totalMouseDistance,
            solve_duration: Date.now() - this.startTime
        };
        
        return this.results;
    }
    
    async solveCanvasChallenge(challenge) {
        return new Promise((resolve) => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const params = challenge.parameters;
            
            // Set canvas dimensions
            canvas.width = params.width || 300;
            canvas.height = params.height || 150;
            
            // Set styles
            ctx.font = params.font || '14px Arial';
            ctx.fillStyle = params.color || '#2d3748';
            
            // Draw text
            ctx.fillText(params.text || 'Challenge Text', 10, 30);
            
            // Draw shapes if specified
            if (params.shapes) {
                params.shapes.forEach((shape, index) => {
                    const x = 50 + (index * 60);
                    const y = 60;
                    
                    switch (shape) {
                        case 'rectangle':
                            ctx.fillRect(x, y, 40, 30);
                            break;
                        case 'circle':
                            ctx.beginPath();
                            ctx.arc(x + 20, y + 15, 15, 0, 2 * Math.PI);
                            ctx.fill();
                            break;
                        case 'line':
                            ctx.beginPath();
                            ctx.moveTo(x, y);
                            ctx.lineTo(x + 40, y + 30);
                            ctx.stroke();
                            break;
                    }
                });
            }
            
            // Apply transformations if specified
            if (params.transformations) {
                ctx.save();
                if (params.transformations.includes('rotate')) {
                    ctx.rotate(0.1);
                }
                if (params.transformations.includes('scale')) {
                    ctx.scale(1.1, 1.1);
                }
                ctx.fillText('Transformed', 10, 120);
                ctx.restore();
            }
            
            // Get canvas data
            const canvasData = canvas.toDataURL();
            
            resolve({
                canvas_data: canvasData,
                width: canvas.width,
                height: canvas.height,
                timestamp: Date.now()
            });
        });
    }
    
    async solveTimingChallenge(challenge) {
        const params = challenge.parameters;
        const iterations = params.iterations || 100;
        const executionTimes = [];
        
        // Perform timing measurements
        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            
            // Perform various operations
            if (params.operations.includes('math')) {
                Math.sqrt(Math.random() * 1000);
            }
            if (params.operations.includes('string')) {
                'test string'.repeat(10).split('').reverse().join('');
            }
            if (params.operations.includes('array')) {
                Array.from({length: 100}, (_, i) => i).sort(() => Math.random() - 0.5);
            }
            
            const end = performance.now();
            executionTimes.push(end - start);
            
            // Small delay to avoid blocking
            if (i % 10 === 0) {
                await new Promise(resolve => setTimeout(resolve, 1));
            }
        }
        
        return {
            execution_times: executionTimes,
            average_time: executionTimes.reduce((a, b) => a + b, 0) / executionTimes.length,
            min_time: Math.min(...executionTimes),
            max_time: Math.max(...executionTimes),
            timestamp: Date.now()
        };
    }
    
    async solveProofOfWork(challenge) {
        const params = challenge.parameters;
        const challengeId = params.challenge_id;
        const target = params.target;
        const difficulty = params.difficulty;
        
        let nonce = 0;
        let hash = '';
        
        // Find nonce that produces hash with required leading zeros
        while (true) {
            const data = challengeId + nonce.toString();
            hash = await this.sha256(data);
            
            if (hash.startsWith(target)) {
                break;
            }
            
            nonce++;
            
            // Yield control periodically to prevent blocking
            if (nonce % 1000 === 0) {
                await new Promise(resolve => setTimeout(resolve, 1));
            }
            
            // Safety limit to prevent infinite loops
            if (nonce > 1000000) {
                console.warn('Proof of work taking too long, using current result');
                break;
            }
        }
        
        return {
            nonce: nonce,
            hash: hash,
            attempts: nonce + 1,
            timestamp: Date.now()
        };
    }
    
    async solveFingerprintChallenge(challenge) {
        const fingerprint = {};
        
        // Screen information
        fingerprint.screen_resolution = `${screen.width}x${screen.height}`;
        fingerprint.screen_color_depth = screen.colorDepth;
        fingerprint.screen_pixel_depth = screen.pixelDepth;
        
        // Browser information
        fingerprint.user_agent = navigator.userAgent;
        fingerprint.language = navigator.language;
        fingerprint.languages = navigator.languages;
        fingerprint.platform = navigator.platform;
        fingerprint.cookie_enabled = navigator.cookieEnabled;
        fingerprint.do_not_track = navigator.doNotTrack;
        
        // Timezone
        fingerprint.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        fingerprint.timezone_offset = new Date().getTimezoneOffset();
        
        // Plugins
        fingerprint.plugins = Array.from(navigator.plugins).map(plugin => ({
            name: plugin.name,
            description: plugin.description,
            filename: plugin.filename
        }));
        
        // WebGL information
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                fingerprint.webgl_info = {
                    vendor: gl.getParameter(gl.VENDOR),
                    renderer: gl.getParameter(gl.RENDERER),
                    version: gl.getParameter(gl.VERSION),
                    shading_language_version: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
                };
            }
        } catch (e) {
            fingerprint.webgl_info = null;
        }
        
        // Audio context
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            fingerprint.audio_context = {
                sample_rate: audioContext.sampleRate,
                state: audioContext.state,
                max_channel_count: audioContext.destination.maxChannelCount
            };
            audioContext.close();
        } catch (e) {
            fingerprint.audio_context = null;
        }
        
        // Fonts detection (simplified)
        fingerprint.fonts = this.detectFonts();
        
        // Hardware concurrency
        fingerprint.hardware_concurrency = navigator.hardwareConcurrency;
        
        // Memory information (if available)
        if (navigator.deviceMemory) {
            fingerprint.device_memory = navigator.deviceMemory;
        }
        
        // Connection information (if available)
        if (navigator.connection) {
            fingerprint.connection = {
                effective_type: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt
            };
        }
        
        fingerprint.timestamp = Date.now();
        
        return fingerprint;
    }
    
    async solveMathChallenge(challenge) {
        const params = challenge.parameters;
        const operations = params.operations || ['addition'];
        const range = params.range || [1, 100];
        const count = params.count || 3;
        
        const answers = [];
        
        for (let i = 0; i < count; i++) {
            const operation = operations[i % operations.length];
            const a = Math.floor(Math.random() * (range[1] - range[0])) + range[0];
            const b = Math.floor(Math.random() * (range[1] - range[0])) + range[0];
            
            let result;
            switch (operation) {
                case 'addition':
                    result = a + b;
                    break;
                case 'subtraction':
                    result = a - b;
                    break;
                case 'multiplication':
                    result = a * b;
                    break;
                case 'division':
                    result = Math.floor(a / b);
                    break;
                case 'modulo':
                    result = a % b;
                    break;
                case 'power':
                    result = Math.pow(a, Math.min(b, 5)); // Limit power to prevent overflow
                    break;
                case 'fibonacci':
                    result = this.fibonacci(Math.min(a, 20)); // Limit to prevent performance issues
                    break;
                case 'prime':
                    result = this.isPrime(a) ? 1 : 0;
                    break;
                default:
                    result = a + b;
            }
            
            answers.push(result);
        }
        
        return {
            answers: answers,
            timestamp: Date.now()
        };
    }
    
    async solveMemoryChallenge(challenge) {
        const params = challenge.parameters;
        const allocationSize = params.allocation_size || 1024 * 1024; // 1MB
        const operations = params.operations || ['fill'];
        const iterations = params.iterations || 3;
        
        const results = [];
        
        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            
            // Allocate memory
            const array = new Array(allocationSize / 4); // Assuming 4 bytes per element
            
            // Perform operations
            if (operations.includes('fill')) {
                for (let j = 0; j < array.length; j++) {
                    array[j] = Math.random();
                }
            }
            
            if (operations.includes('sort')) {
                array.sort();
            }
            
            if (operations.includes('search')) {
                const target = Math.random();
                array.indexOf(target);
            }
            
            const end = performance.now();
            results.push({
                iteration: i,
                duration: end - start,
                memory_used: array.length * 4 // Approximate bytes
            });
            
            // Clean up
            array.length = 0;
            
            // Yield control
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        
        return {
            results: results,
            average_duration: results.reduce((sum, r) => sum + r.duration, 0) / results.length,
            timestamp: Date.now()
        };
    }
    
    // Helper methods
    async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    detectFonts() {
        const testFonts = [
            'Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Verdana',
            'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
            'Trebuchet MS', 'Arial Black', 'Impact'
        ];
        
        const detectedFonts = [];
        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';
        
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        
        // Test each font
        testFonts.forEach(font => {
            context.font = `${testSize} ${font}, monospace`;
            const width = context.measureText(testString).width;
            
            context.font = `${testSize} monospace`;
            const monoWidth = context.measureText(testString).width;
            
            if (width !== monoWidth) {
                detectedFonts.push(font);
            }
        });
        
        return detectedFonts;
    }
    
    fibonacci(n) {
        if (n <= 1) return n;
        let a = 0, b = 1;
        for (let i = 2; i <= n; i++) {
            [a, b] = [b, a + b];
        }
        return b;
    }
    
    isPrime(n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 === 0 || n % 3 === 0) return false;
        
        for (let i = 5; i * i <= n; i += 6) {
            if (n % i === 0 || n % (i + 2) === 0) return false;
        }
        return true;
    }
}

// Global challenge solver instance
window.challengeSolver = new ChallengeSolver();

// Auto-solve challenges when they appear
document.addEventListener('DOMContentLoaded', function() {
    // Look for challenge data in the page
    const challengeScript = document.querySelector('script[data-challenge]');
    if (challengeScript) {
        try {
            const challengeData = JSON.parse(challengeScript.getAttribute('data-challenge'));
            solveChallengeAndSubmit(challengeData);
        } catch (e) {
            console.error('Failed to parse challenge data:', e);
        }
    }
});

async function solveChallengeAndSubmit(challengeData) {
    try {
        console.log('Starting challenge resolution...');
        
        // Show loading indicator
        showChallengeProgress('Solving browser verification challenges...');
        
        // Solve the challenge
        const results = await window.challengeSolver.solveChallenge(challengeData);
        
        // Submit results
        showChallengeProgress('Submitting verification results...');
        
        const response = await fetch('/api/verify-browser', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                challenge_id: challengeData.challenge_id,
                results: results,
                timestamp: Date.now()
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.verified) {
                showChallengeProgress('Verification successful! Redirecting...');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                showChallengeProgress('Verification failed. Please try again.');
            }
        } else {
            throw new Error('Verification request failed');
        }
        
    } catch (error) {
        console.error('Challenge solving failed:', error);
        showChallengeProgress('Verification failed. Please refresh the page.');
    }
}

function showChallengeProgress(message) {
    let progressDiv = document.getElementById('challenge-progress');
    if (!progressDiv) {
        progressDiv = document.createElement('div');
        progressDiv.id = 'challenge-progress';
        progressDiv.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            z-index: 10000;
            font-family: Arial, sans-serif;
            text-align: center;
        `;
        document.body.appendChild(progressDiv);
    }
    progressDiv.innerHTML = `
        <div style="margin-bottom: 10px;">
            <div style="width: 40px; height: 40px; border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto;"></div>
        </div>
        <div>${message}</div>
        <style>
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    `;
}

