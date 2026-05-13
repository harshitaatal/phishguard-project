// background.js

const EXCLUDED_DOMAINS = [
    'localhost',
    '127.0.0.1',
    'google.com' // Example exclusion
];

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only intercept main frame navigation
    if (details.frameId !== 0) return;

    const url = new URL(details.url);
    
    // Skip internal chrome pages and extension pages
    if (url.protocol === 'chrome:' || url.protocol === 'chrome-extension:') return;
    
    // Skip excluded domains
    if (EXCLUDED_DOMAINS.some(domain => url.hostname.includes(domain))) return;

    // Check if we already scanned this URL in this session
    chrome.storage.session.get([details.url], (result) => {
        if (result[details.url] === 'safe') {
            console.log("URL already scanned and safe:", details.url);
            return;
        }

        // Redirect to scanner page
        const scannerUrl = chrome.runtime.getURL(`scanner.html?url=${encodeURIComponent(details.url)}`);
        
        // We can't cancel navigation in webNavigation, so we update the tab
        chrome.tabs.update(details.tabId, { url: scannerUrl });
    });
});
