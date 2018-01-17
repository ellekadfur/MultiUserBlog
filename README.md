Hello!

This site is a blog that is hosted at
https://testudacity-164105.appspot.com/.

To run this site in the browser just copy the link and
put it in the browser address bar. From
there you will be directed to login or
sign up. Once you decide either course
of action, you will be directed to the
welcome page.  From there you can create
your own blog post, view blogs posted,
like a blog post, edit your own blog post,
edit a comment, or comment on a blog, or
log out.

To run this site locally:
1)Open Terminal and type cd to the directory
2)Go here in the browser https://cloud.google.com/appengine/docs/standard/python/quickstart to download Google App Engine, if you need help with those insructions here's more information:
https://cloud.google.com/sdk/docs/

3)Make sure to add SDK to your path by Install script:
./google-cloud-sdk/install.sh

4) Run gcloud init to initialize the SDK:
./google-cloud-sdk/bin/gcloud init

5) make sure to (——Restart Terminal——)

6)Start Server:
 dev_appserver.py . in file where app.yaml is

7) Open browser at:
http://localhost:8080/signup to get started
http://localhost:8080/login if you already have an account

here are some other useful commands and info:
1)Disable User Reporting:
gcloud config set disable_usage_reporting true

2)To delete
gcloud app versions list
gcloud app versions delete 20170413t201649


3)Error codes:
Error code that start with 4 means it’s an error on client (browser)

* **lamarjaycaaddfiir@gmail.com** - *Initial work*

Enjoy!
