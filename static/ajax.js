document.addEventListener('DOMContentLoaded', function () {
    const container = document.getElementById('data-container');
    if (!container) return;

    // Handle Pagination Clicks (Event Delegation)
    container.addEventListener('click', function (e) {
        const link = e.target.closest('.ajax-link');
        if (link) {
            e.preventDefault();
            loadData(link.href);
        }
    });

    // Handle Rows Per Page Change (Event Delegation / Direct attachment if outside container)
    // The dropdown is usually outside the data-container in my current design (header).
    // Now using class selector to avoid ID conflicts and support multiple.
    const perPageSelects = document.querySelectorAll('.row-limit-select');

    perPageSelects.forEach(select => {
        // Remove old onchange handler if possible or just override
        select.removeAttribute('onchange');

        select.addEventListener('change', function (e) {
            e.preventDefault();
            const form = select.closest('form');
            const url = new URL(form.action);
            const params = new URLSearchParams(new FormData(form));
            // Ensure month is preserved if present in form or url
            url.search = params.toString();
            loadData(url.toString());
        });
    });

    function loadData(url) {
        // Show loading state?
        container.style.opacity = '0.5';

        // Append ajax=1 to URL
        const urlObj = new URL(url, window.location.origin);
        urlObj.searchParams.set('ajax', '1');

        fetch(urlObj.toString(), {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
            .then(response => {
                if (!response.ok) throw new Error('Network response was not ok');
                return response.text();
            })
            .then(html => {
                container.innerHTML = html;
                container.style.opacity = '1';
                // Scroll to top of table?
                // container.scrollIntoView({ behavior: 'smooth' });
            })
            .catch(error => {
                console.error('Error:', error);
                container.style.opacity = '1';
                alert('Failed to load data.');
            });
    }
});
