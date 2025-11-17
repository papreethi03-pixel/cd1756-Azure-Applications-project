"""
Routes and views for the Flask application.
"""

from datetime import datetime
from typing import Optional

from flask import (
    render_template,
    flash,
    redirect,
    request,
    session,
    url_for,
)
from werkzeug.urls import url_parse
from config import Config
from FlaskWebProject import app, db, LOG
from FlaskWebProject.forms import LoginForm, PostForm
from flask_login import (
    current_user,
    login_user,
    logout_user,
    login_required,
)

from FlaskWebProject.models import User, Post
import msal
import uuid

# ----------------------------------------------------------------------
# Global URL for uploaded images (Azure Blob Storage)
# ----------------------------------------------------------------------
imageSourceUrl = (
    f"https://{app.config['BLOB_ACCOUNT']}"
    f".blob.core.windows.net/{app.config['BLOB_CONTAINER']}/"
)


# ----------------------------------------------------------------------
# Home page – list all posts
# ----------------------------------------------------------------------
@app.route("/")
@app.route("/home")
@login_required
def home() -> str:
    user = User.query.filter_by(username=current_user.username).first_or_404()
    posts = Post.query.all()
    return render_template(
        "index.html",
        title="Home Page",
        posts=posts,
    )


# ----------------------------------------------------------------------
# Create a new post
# ----------------------------------------------------------------------
@app.route("/new_post", methods=["GET", "POST"])
@login_required
def new_post() -> str:
    form = PostForm(request.form)
    if form.validate_on_submit():
        post = Post()
        post.save_changes(form, request.files["image_path"], current_user.id, new=True)
        return redirect(url_for("home"))

    return render_template(
        "post.html",
        title="Create Post",
        imageSource=imageSourceUrl,
        form=form,
    )


# ----------------------------------------------------------------------
# Edit an existing post
# ----------------------------------------------------------------------
@app.route("/post/<int:id>", methods=["GET", "POST"])
@login_required
def post(id: int) -> str:
    post_obj = Post.query.get_or_404(id)
    form = PostForm(formdata=request.form, obj=post_obj)

    if form.validate_on_submit():
        post_obj.save_changes(form, request.files["image_path"], current_user.id)
        return redirect(url_for("home"))

    return render_template(
        "post.html",
        title="Edit Post",
        imageSource=imageSourceUrl,
        form=form,
    )


# ----------------------------------------------------------------------
# Local login (username / password)
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password")
            LOG.warning(
                "WARNING: Login unsuccessful – invalid username or password for user: %s",
                form.username.data,
            )
            return redirect(url_for("login"))

        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("home")
        return redirect(next_page)

    # Prepare Microsoft login URL
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    return render_template(
        "login.html",
        title="Sign In",
        form=form,
        auth_url=auth_url,
    )


# ----------------------------------------------------------------------
# OAuth callback from Microsoft Identity
# ----------------------------------------------------------------------
@app.route(Config.REDIRECT_PATH)  # must match redirect_uri in Azure AD
def authorized() -> str:
    if request.args.get("state") != session.get("state"):
        return redirect(url_for("home"))

    if "error" in request.args:
        return render_template("auth_error.html", result=request.args)

    if request.args.get("code"):
        cache = _load_cache()
        msal_app = _build_msal_app(cache=cache)
        result = msal_app.acquire_token_by_authorization_code(
            request.args["code"],
            scopes=Config.SCOPE,
            redirect_uri=url_for("authorized", _external=True, _scheme="https"),
        )

        if "error" in result:
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")
        # For demo we always log the user in as the admin account
        admin_user = User.query.filter_by(username="admin").first()
        login_user(admin_user)
        _save_cache(cache)
        LOG.info("INFO: User logged in via Microsoft Identity")

    return redirect(url_for("home"))


# ----------------------------------------------------------------------
# Logout
# ----------------------------------------------------------------------
@app.route("/logout")
def logout() -> str:
    logout_user()
    if session.get("user"):  # Microsoft login session
        session.clear()
        logout_url = (
            f"{Config.AUTHORITY}/oauth2/v2.0/logout"
            f"?post_logout_redirect_uri={url_for('login', _external=True)}"
        )
        return redirect(logout_url)

    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# MSAL helper functions
# ----------------------------------------------------------------------
def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(
    cache: Optional[msal.SerializableTokenCache] = None, authority: Optional[str] = None
) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        Config.CLIENT_ID,
        authority=authority or Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET,
        token_cache=cache,
    )


def _build_auth_url(
    authority: Optional[str] = None, scopes: Optional[list] = None, state: Optional[str] = None
) -> str:
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for("authorized", _external=True, _scheme="https"),
    )
