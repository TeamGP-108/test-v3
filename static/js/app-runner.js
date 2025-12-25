document.addEventListener('DOMContentLoaded', function() {
    // Handle stop app form
    const stopAppForm = document.getElementById('stop-app-form');
    if (stopAppForm) {
        stopAppForm.addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to stop the application?')) {
                e.preventDefault();
            }
        });
    }
    
    // Log refresh functionality
    const logContent = document.getElementById('log-content');
    if (logContent) {
        // Initial fetch of logs
        refreshLogs();
    }
});

// Function to refresh application logs
function refreshLogs() {
    const logContent = document.getElementById('log-content');
    if (!logContent) return;
    
    const projectId = logContent.dataset.projectId;
    
    fetch(`/project/${projectId}/logs`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Only update if content has changed
                if (logContent.textContent !== data.log_content) {
                    // Store previous scroll position and check if we were at the bottom
                    const wasAtBottom = logContent.scrollTop + logContent.clientHeight >= logContent.scrollHeight - 10;
                    
                    // Update content
                    logContent.textContent = data.log_content;
                    
                    // Auto-scroll only if we were already at the bottom or if this is the first content
                    if (wasAtBottom || !logContent.dataset.hasScrolled) {
                        logContent.scrollTop = logContent.scrollHeight;
                        // Mark as scrolled
                        logContent.dataset.hasScrolled = "true";
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error fetching logs:', error);
        });
}
