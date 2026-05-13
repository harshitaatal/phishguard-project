// scanner.js

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    
    if (!targetUrl) {
        document.getElementById('status-title').textContent = "Error: No URL provided";
        return;
    }

    document.getElementById('target-url').textContent = targetUrl;
    
    // UI Elements
    const progressBar = document.getElementById('progress-bar');
    const statusTitle = document.getElementById('status-title');
    const statusIcon = document.getElementById('status-icon');
    const confidenceValue = document.getElementById('confidence-value');
    const actionPanel = document.getElementById('action-panel');
    const proceedBtn = document.getElementById('proceed-btn');
    const backBtn = document.getElementById('back-btn');
    const mainPanel = document.querySelector('.glass-panel');

    // Simulate progress while waiting for API
    let progress = 0;
    const progressInterval = setInterval(() => {
        if (progress < 90) {
            progress += Math.random() * 5;
            progressBar.style.width = `${progress}%`;
        }
    }, 200);

    // Call Flask API
    fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: targetUrl })
    })
    .then(response => response.json())
    .then(data => {
        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        
        if (data.error) {
            statusTitle.textContent = "Analysis Failed";
            confidenceValue.textContent = "Error";
            return;
        }

        setTimeout(() => {
            if (data.is_safe) {
                // SAFE STATE
                document.body.classList.add('safe');
                statusTitle.textContent = "Website Verified Safe";
                statusIcon.textContent = "✅";
                confidenceValue.textContent = `${data.safe_percentage}% Confidence`;
                
                // Show actions
                actionPanel.style.display = 'flex';
                proceedBtn.textContent = "Proceed to Website";
                
                // Store in session storage so we don't scan again this session
                chrome.storage.session.set({ [targetUrl]: 'safe' });

                // Optional: Auto-redirect after 3 seconds
                let count = 3;
                proceedBtn.textContent = `Redirecting in ${count}s...`;
                const countdown = setInterval(() => {
                    count--;
                    if (count > 0) {
                        proceedBtn.textContent = `Redirecting in ${count}s...`;
                    } else {
                        clearInterval(countdown);
                        window.location.href = targetUrl;
                    }
                }, 1000);

                proceedBtn.onclick = () => {
                    clearInterval(countdown);
                    window.location.href = targetUrl;
                };

            } else {
                // PHISHING STATE
                document.body.classList.add('phishing');
                statusTitle.textContent = "Phishing Threat Detected!";
                statusIcon.textContent = "⚠️";
                confidenceValue.textContent = `${data.unsafe_percentage}% Risk`;
                
                // Show actions
                actionPanel.style.display = 'flex';
                proceedBtn.textContent = "Proceed Anyway (Unsafe)";
                proceedBtn.classList.remove('btn-primary');
                proceedBtn.classList.add('btn-secondary');
                
                backBtn.onclick = () => {
                    window.history.back();
                    if (window.history.length <= 1) {
                        window.close();
                    }
                };

                proceedBtn.onclick = () => {
                    if (confirm("WARNING: This site is flagged as phishing. Your personal data may be at risk. Are you sure you want to proceed?")) {
                        chrome.storage.session.set({ [targetUrl]: 'safe' }); // Treat as safe for this session if user insists
                        window.location.href = targetUrl;
                    }
                };
            }
        }, 800);
    })
    .catch(error => {
        console.error('Error:', error);
        clearInterval(progressInterval);
        statusTitle.textContent = "Connection Error";
        document.getElementById('target-url').textContent = "Make sure the PhishGuard backend is running on localhost:5000";
    });
});
