// Function to show error messages
function showError(message) {
    document.getElementById('loading-spinner').style.display = 'none'; // Hide the loading spinner
    document.getElementById('output').textContent = message;
}

// Function to show success messages
function showSuccess(message) {
    document.getElementById('loading-spinner').style.display = 'none'; // Hide the loading spinner
    document.getElementById('output').innerHTML = message; // Use innerHTML for rendering HTML content
    document.getElementById('download-button').style.display = 'block'; // Show the download button
}

// Handle form submission
document.getElementById('scraping-form').addEventListener('submit', function(e) {
    e.preventDefault();
    document.getElementById('loading-spinner').style.display = 'block'; // Show the loading spinner

    const userInput = document.getElementById('user-input').value.trim();
    const fileFormat = document.getElementById('file-format').value;
    const fileName = document.getElementById('file-name').value.trim();

    // Validate user input
    if (!userInput || !fileFormat || !fileName) {
        showError('Please fill in all fields.');
        return;
    }

    // Prepare form data for the request
    const formData = new FormData();
    formData.append('query', userInput);

    fetch('http://127.0.0.1:5000/summary', {
        method: 'POST',
        body: formData,
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data['combined data']) {
            showSuccess(data['combined data']);
        } else {
            showError('An error occurred while scraping data.');
        }
    })
    .catch(error => {
        showError(`An unexpected error occurred: ${error.message}`);
    });
});

// Handle file download
document.getElementById('download-button').addEventListener('click', function() {
    const userInput = document.getElementById('user-input').value.trim();
    const fileFormat = document.getElementById('file-format').value;
    const fileName = document.getElementById('file-name').value.trim();

    // Validate user input
    if (!userInput || !fileFormat || !fileName) {
        showError('Please fill in all fields.');
        return;
    }

    const formData = new FormData();
    formData.append('query', userInput);
    formData.append('format', fileFormat);
    formData.append('filename', fileName);

    fetch('http://127.0.0.1:5000/scrape', {
        method: 'POST',
        body: formData,
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${fileName}.${fileFormat}`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url); // Clean up
    })
    .catch(error => {
        showError(`An unexpected error occurred during file download: ${error.message}`);
    });
});
