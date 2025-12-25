document.addEventListener('DOMContentLoaded', function() {
    // Handle file upload preview
    const fileUpload = document.getElementById('file-upload');
    const filePreview = document.getElementById('file-preview');
    
    if (fileUpload && filePreview) {
        fileUpload.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                filePreview.textContent = `Selected: ${file.name} (${formatFileSize(file.size)})`;
            } else {
                filePreview.textContent = '';
            }
        });
    }
    
    // Confirm delete project
    const deleteProjectForms = document.querySelectorAll('#delete-project-form');
    deleteProjectForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const projectName = this.dataset.projectName;
            if (confirm(`Are you sure you want to delete the project "${projectName}"? This action cannot be undone.`)) {
                this.submit();
            }
        });
    });
    
    // Confirm delete file
    const deleteFileForms = document.querySelectorAll('.delete-file-form');
    deleteFileForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const filename = this.dataset.filename;
            if (confirm(`Are you sure you want to delete the file "${filename}"? This action cannot be undone.`)) {
                this.submit();
            }
        });
    });
    
    // Confirm delete folder
    const deleteFolderForms = document.querySelectorAll('.delete-folder-form');
    deleteFolderForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const folderName = this.dataset.folderName;
            if (confirm(`Are you sure you want to delete the folder "${folderName}" and all its contents? This action cannot be undone.`)) {
                this.submit();
            }
        });
    });
});

// Utility function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
