# David Zheng's website

Hi, welcome to my github backend for my website.

## Local development

On Windows, open this repository in WSL and use the Ruby installation there.
The lockfile uses Bundler 2.7.2, which requires Ruby 3.2 or newer. Install that
version of Bundler with `gem install bundler -v 2.7.2` if needed.

```sh
bundle install
bundle exec jekyll serve --force_polling --destination .jekyll-cache/preview
```

Open [http://localhost:4000](http://localhost:4000). Polling detects source
changes when the checkout is on a Windows drive. To rebuild the checked-in
`_site` output, run `bundle exec jekyll build`.

The Sass partials in `_sass/minima` are adapted from Minima 2.5.2. They use the
Sass module API and retain the theme's original styles.

## Publishing the site

Replace `assets/cv.pdf` and `_bibliography/references.bib` to update the CV
and publications. GitHub Actions installs the locked gems and builds the site
from source. A push to `main` deploys the site after the build succeeds.
Push a branch named `build/<name>` to test the same build without deploying.
