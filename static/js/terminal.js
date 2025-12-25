// Terminal functionality using XTerm.js
let terminal;
const commandHistory = [];
let historyIndex = -1;
let currentCommandBuffer = '';

function initTerminal() {
    const terminalOutputEl = document.getElementById('terminal-output');
    const terminalForm = document.getElementById('terminal-form');
    const terminalCommandInput = document.getElementById('terminal-command');
    const clearTerminalBtn = document.getElementById('clear-terminal');
    
    if (!terminalOutputEl || !terminalForm || !terminalCommandInput) return;
    
    // Initialize terminal with welcome message
    terminalOutputEl.innerHTML = `<div class="terminal-output-line">Welcome to AppHost Terminal</div>
<div class="terminal-output-line">Type 'help' for available commands</div>
<div class="terminal-output-line">Working directory: project root</div>
<div class="terminal-output-line">-----------------------------------------</div>`;

    // Handle command submission
    terminalForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const command = terminalCommandInput.value.trim();
        if (!command) return;
        
        // Add command to history
        commandHistory.push(command);
        historyIndex = commandHistory.length;
        
        // Clear input
        terminalCommandInput.value = '';
        
        // Display the command in terminal
        appendToTerminal(`<div class="terminal-command-line"><span class="terminal-prompt">$</span><span class="terminal-command">${escapeHTML(command)}</span></div>`);
        
        // Execute the command
        executeCommand(command);
    });
    
    // Handle arrow up/down for command history
    terminalCommandInput.addEventListener('keydown', function(e) {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex === commandHistory.length) {
                // Save the current input before navigating history
                currentCommandBuffer = terminalCommandInput.value;
            }
            
            if (historyIndex > 0) {
                historyIndex--;
                terminalCommandInput.value = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                terminalCommandInput.value = commandHistory[historyIndex];
            } else if (historyIndex === commandHistory.length - 1) {
                historyIndex = commandHistory.length;
                terminalCommandInput.value = currentCommandBuffer;
            }
        }
    });
    
    // Clear terminal button
    if (clearTerminalBtn) {
        clearTerminalBtn.addEventListener('click', function() {
            terminalOutputEl.innerHTML = `<div class="terminal-output-line">Terminal cleared</div>`;
        });
    }
    
    // Focus the terminal input when the terminal container is clicked
    document.querySelector('.terminal-container')?.addEventListener('click', function() {
        terminalCommandInput.focus();
    });
}

function appendToTerminal(html) {
    const terminalOutputEl = document.getElementById('terminal-output');
    if (!terminalOutputEl) return;
    
    terminalOutputEl.innerHTML += html;
    terminalOutputEl.scrollTop = terminalOutputEl.scrollHeight;
}

function executeCommand(command) {
    const projectId = document.getElementById('terminal-form')?.dataset.projectId;
    if (!projectId) {
        appendToTerminal(`<div class="terminal-output-line terminal-error">Error: Project ID not found</div>`);
        return;
    }
    
    // Add loading indicator
    const loadingId = 'loading-' + Date.now();
    appendToTerminal(`<div id="${loadingId}" class="terminal-output-line">Executing command...</div>`);
    
    // Special case for help command
    if (command.toLowerCase() === 'help') {
        document.getElementById(loadingId)?.remove();
        appendToTerminal(`<div class="terminal-output-line">Available commands:</div>
<div class="terminal-output-line">- pip install [package]: Install Python packages</div>
<div class="terminal-output-line">- pip list: List installed packages</div>
<div class="terminal-output-line">- pip freeze: Output installed packages in requirements format</div>
<div class="terminal-output-line">- ls: List files in the current directory</div>
<div class="terminal-output-line">- cat [file]: Display the contents of a file</div>
<div class="terminal-output-line">- cd [directory]: Change the working directory</div>
<div class="terminal-output-line">- clear: Clear the terminal screen</div>
<div class="terminal-output-line">- help: Show this help menu</div>`);
        return;
    }
    
    // Special case for clear command
    if (command.toLowerCase() === 'clear') {
        document.getElementById('terminal-output').innerHTML = `<div class="terminal-output-line">Terminal cleared</div>`;
        return;
    }
    
    // Execute the command through the server
    fetch(`/project/${projectId}/terminal/run`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'command': command
        })
    })
    .then(response => response.json())
    .then(data => {
        // Remove loading indicator
        document.getElementById(loadingId)?.remove();
        
        if (data.success) {
            const output = data.output || 'Command executed successfully with no output';
            appendToTerminal(`<div class="terminal-output-line">${escapeHTML(output).replace(/\n/g, '<br>')}</div>`);
        } else {
            const errorMessage = data.message || 'An error occurred while executing the command';
            appendToTerminal(`<div class="terminal-output-line terminal-error">${escapeHTML(errorMessage)}</div>`);
        }
    })
    .catch(error => {
        // Remove loading indicator
        document.getElementById(loadingId)?.remove();
        
        console.error('Error executing command:', error);
        appendToTerminal(`<div class="terminal-output-line terminal-error">Network error: Could not execute command</div>`);
    });
}

// Helper function to escape HTML
function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Register AutoComplete for common commands
function registerTerminalAutocomplete() {
    const commandInput = document.getElementById('terminal-command');
    if (!commandInput) return;
    
    const commonCommands = [
        'pip install ',
        'pip list',
        'pip freeze',
        'pip uninstall ',
        'ls',
        'cd ',
        'cat ',
        'python ',
        'clear',
        'help'
    ];
    
    // Simple autocomplete implementation
    commandInput.addEventListener('input', function() {
        const inputVal = this.value.toLowerCase();
        if (inputVal && inputVal.length > 1) {
            const match = commonCommands.find(cmd => cmd.toLowerCase().startsWith(inputVal));
            if (match) {
                // Create a datalist element for suggestions
                let datalist = document.getElementById('command-suggestions');
                if (!datalist) {
                    datalist = document.createElement('datalist');
                    datalist.id = 'command-suggestions';
                    document.body.appendChild(datalist);
                    commandInput.setAttribute('list', 'command-suggestions');
                }
                
                // Clear existing options
                datalist.innerHTML = '';
                
                // Add matching commands
                commonCommands.forEach(cmd => {
                    if (cmd.toLowerCase().includes(inputVal)) {
                        const option = document.createElement('option');
                        option.value = cmd;
                        datalist.appendChild(option);
                    }
                });
            }
        }
    });
    
    // Handle Tab key for completion
    commandInput.addEventListener('keydown', function(e) {
        if (e.key === 'Tab') {
            e.preventDefault();
            const inputVal = this.value.toLowerCase();
            if (inputVal) {
                const matches = commonCommands.filter(cmd => cmd.toLowerCase().startsWith(inputVal));
                if (matches.length === 1) {
                    this.value = matches[0];
                }
            }
        }
    });
}

// Initialize terminal functionality on page load
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('terminal-form')) {
        initTerminal();
        registerTerminalAutocomplete();
    }
});
