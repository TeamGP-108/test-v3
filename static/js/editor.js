// CodeMirror editor initialization and management
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the code editor if present
    const codeEditorTextarea = document.getElementById('code-editor');
    if (!codeEditorTextarea) return;

    // Get file extension to determine mode
    const fileExtension = codeEditorTextarea.dataset.fileExtension || '';
    
    // Determine editor mode based on file extension
    let mode = 'text/plain';
    switch (fileExtension) {
        case 'py':
            mode = 'python';
            break;
        case 'js':
            mode = 'javascript';
            break;
        case 'html':
            mode = 'htmlmixed';
            break;
        case 'css':
            mode = 'css';
            break;
        case 'json':
            mode = 'application/json';
            break;
        case 'md':
            mode = 'markdown';
            break;
        case 'xml':
            mode = 'xml';
            break;
        // Add more file types as needed
    }

    // Initialize CodeMirror
    const editor = CodeMirror.fromTextArea(codeEditorTextarea, {
        mode: mode,
        theme: 'material-darker',
        lineNumbers: true,
        lineWrapping: true,
        matchBrackets: true,
        autoCloseBrackets: true,
        autoCloseTags: true,
        indentUnit: 4,
        tabSize: 4,
        indentWithTabs: false,
        extraKeys: {
            "F11": function(cm) {
                cm.setOption("fullScreen", !cm.getOption("fullScreen"));
            },
            "Esc": function(cm) {
                if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false);
            }
        }
    });

    // Save the editor instance globally for later use
    window.codeEditor = editor;

    // Function to save file
    window.saveFile = function() {
        const saveForm = document.getElementById('save-file-form');
        if (!saveForm) return;

        const projectId = saveForm.dataset.projectId;
        const fileId = saveForm.dataset.fileId;
        const content = window.codeEditor.getValue();
        const commitMessage = document.getElementById('commit-message')?.value || 'Update file';
        
        // Update save status
        const saveStatus = document.getElementById('save-status');
        if (saveStatus) {
            saveStatus.textContent = 'Saving...';
            saveStatus.classList.remove('d-none', 'text-success', 'text-danger');
            saveStatus.classList.add('text-warning');
        }
        
        // Send the content to the server
        fetch(`/project/${projectId}/file/${fileId}/save`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'content': content,
                'commit_message': commitMessage
            })
        })
        .then(response => response.json())
        .then(data => {
            if (saveStatus) {
                if (data.success) {
                    saveStatus.textContent = 'Saved!';
                    saveStatus.classList.remove('text-warning');
                    saveStatus.classList.add('text-success');
                    
                    // Clear after a few seconds
                    setTimeout(() => {
                        saveStatus.classList.add('d-none');
                    }, 3000);
                } else {
                    saveStatus.textContent = `Error: ${data.message}`;
                    saveStatus.classList.remove('text-warning');
                    saveStatus.classList.add('text-danger');
                }
            }
        })
        .catch(error => {
            console.error('Error saving file:', error);
            if (saveStatus) {
                saveStatus.textContent = 'Error saving file';
                saveStatus.classList.remove('text-warning');
                saveStatus.classList.add('text-danger');
            }
        });
    };

    // Set up keyboard shortcuts for saving
    editor.setOption('extraKeys', {
        ...editor.getOption('extraKeys'),
        'Ctrl-S': saveFile,
        'Cmd-S': saveFile  // For Mac users
    });
});
