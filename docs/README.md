# Galaxy Bug Bounty Checklist Documentation

This directory contains the GitHub Pages documentation for the Galaxy Bug Bounty Checklist project.

## 🚀 Quick Start

### Local Development

1. **Install Dependencies**
   ```bash
   cd docs
   bundle install
   ```

2. **Serve Locally**
   ```bash
   bundle exec jekyll serve
   ```

3. **Access Documentation**
   - Local: http://localhost:4000
   - GitHub Pages: https://0xmaximus.github.io/Galaxy-Bugbounty-Checklist

### GitHub Pages Deployment

The documentation is automatically deployed to GitHub Pages when changes are pushed to the main branch.

## 📁 Directory Structure

```
docs/
├── _config.yml          # Jekyll configuration
├── _layouts/            # Page layouts
│   ├── default.html     # Default layout
│   └── vulnerability.html # Vulnerability page layout
├── _pages/              # Documentation pages
│   ├── vulnerabilities.md
│   ├── methodology.md
│   ├── tools.md
│   ├── resources.md
│   └── [vulnerability-pages].md
├── _includes/           # Reusable components
├── assets/              # Static assets
│   ├── css/            # Stylesheets
│   └── js/             # JavaScript
├── Gemfile             # Ruby dependencies
└── index.html          # Homepage redirect
```

## 🎨 Customization

### Adding New Vulnerability Pages

1. Create a new markdown file in `_pages/`
2. Use the vulnerability layout:
   ```yaml
   ---
   layout: vulnerability
   title: Vulnerability Name
   description: Brief description
   severity: High/Medium/Low
   category: Category Name
   owasp: A03:2021
   permalink: /vulnerabilities/vulnerability-name/
   ---
   ```

3. Add to the vulnerabilities index page

### Styling

- CSS: `assets/css/style.css`
- JavaScript: `assets/js/main.js`
- Layouts: `_layouts/`

### Configuration

- Jekyll config: `_config.yml`
- Navigation: Update `_config.yml` navigation section
- SEO: Configure in `_config.yml` seo section

## 📚 Content Guidelines

### Writing Style

- Use clear, concise language
- Include practical examples
- Provide step-by-step instructions
- Include code snippets with syntax highlighting
- Add references and further reading

### Vulnerability Documentation

Each vulnerability page should include:

1. **Overview** - Description and impact
2. **Attack Techniques** - Detailed attack methods
3. **Testing Methodology** - Step-by-step testing approach
4. **Tools & Automation** - Relevant tools and scripts
5. **Prevention & Mitigation** - Security controls and best practices
6. **References** - Additional resources and documentation

### Code Examples

- Use proper syntax highlighting
- Include comments explaining complex parts
- Provide both basic and advanced examples
- Test all code examples before publishing

## 🔧 Development

### Prerequisites

- Ruby 3.1+
- Bundler
- Jekyll 4.3+

### Commands

```bash
# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Build for production
bundle exec jekyll build

# Check for issues
bundle exec jekyll doctor
```

### Troubleshooting

1. **Bundle Issues**
   ```bash
   bundle update
   bundle install
   ```

2. **Jekyll Issues**
   ```bash
   bundle exec jekyll clean
   bundle exec jekyll serve --trace
   ```

3. **GitHub Pages Issues**
   - Check GitHub Actions workflow
   - Verify Jekyll version compatibility
   - Check for unsupported plugins

## 📖 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Submit a pull request

### Content Contributions

- Follow the established format
- Include practical examples
- Test all code snippets
- Add appropriate references
- Update navigation if needed

## 📄 License

This documentation is part of the Galaxy Bug Bounty Checklist project and follows the same license terms.

---

**Happy Documenting! 📚**