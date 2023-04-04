bundle exec jekyll build
scp -r _site davidzheng@18.220.149.166:~/
ssh davidzheng@18.220.149.166 "rm -rf old_public_html && mv public_html old_public_html && mv _site/ public_html"
