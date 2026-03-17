const NAV_SECTIONS = [
  {
    title: 'Getting Started',
    items: [
      { href: 'index.html', label: 'What is Qualys MCP?' },
      { href: 'getting-started/index.html', label: 'Overview' },
      { href: 'getting-started/installation.html', label: 'Installation' },
      { href: 'getting-started/configuration.html', label: 'Configuration' }
    ]
  },
  {
    title: 'Tools',
    items: [
      { href: 'tools/index.html', label: 'All Tools (35)' },
      { href: 'tools/vulnerability-management.html', label: 'Vulnerability Management' },
      { href: 'tools/threat-intelligence.html', label: 'Threat Intelligence' },
      { href: 'tools/asset-management.html', label: 'Asset Management' },
      { href: 'tools/cloud-security.html', label: 'Cloud Security' },
      { href: 'tools/compliance.html', label: 'Compliance' },
      { href: 'tools/operations.html', label: 'Operations' }
    ]
  },
  {
    title: 'Reference',
    items: [
      { href: 'questions/index.html', label: 'Customer Questions' },
      { href: 'examples/index.html', label: 'Examples' },
      { href: 'architecture/index.html', label: 'Architecture' },
      { href: 'performance/index.html', label: 'Performance' },
      { href: 'gaps/index.html', label: 'Coverage Gaps' }
    ]
  }
];

function getBasePath() {
  const path = window.location.pathname;
  const parts = path.split('/');
  const docsIndex = parts.findIndex(p => p === 'docs');
  if (docsIndex === -1) {
    if (parts.length > 2 && parts[parts.length - 2] !== '') {
      return '../';
    }
    return '';
  }
  const depth = parts.length - docsIndex - 2;
  return '../'.repeat(depth);
}

function renderSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  if (sidebar.querySelector('.sidebar-section')) {
    highlightCurrentPage(sidebar);
    return;
  }

  const basePath = getBasePath();
  const currentPath = window.location.pathname;

  let html = '<div class="sidebar-header"><h2>MCP Server Docs</h2></div>';

  NAV_SECTIONS.forEach(section => {
    html += `<div class="sidebar-section">`;
    html += `<div class="sidebar-section-title">${section.title}</div>`;
    html += `<ul class="sidebar-nav">`;

    section.items.forEach(item => {
      const href = basePath + item.href;
      const isActive = currentPath.endsWith(item.href) ||
                       (item.href === 'index.html' && currentPath.endsWith('/'));
      const activeClass = isActive ? ' class="active"' : '';
      html += `<li><a href="${href}"${activeClass}>${item.label}</a></li>`;
    });

    html += `</ul></div>`;
  });

  sidebar.innerHTML = html;
}

function highlightCurrentPage(sidebar) {
  const currentPath = window.location.pathname;
  const links = sidebar.querySelectorAll('.sidebar-nav a');
  links.forEach(link => {
    link.classList.remove('active');
    const href = link.getAttribute('href');
    if (href && currentPath.endsWith(href.replace(/\.\.\//g, '').replace('./', ''))) {
      link.classList.add('active');
    }
  });
}

document.addEventListener('DOMContentLoaded', renderSidebar);
