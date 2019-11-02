# HERE WE GONNA PUT ALL ABOUT OUR VIEWS IN THE MAIN BLUEPRINT

from flask import render_template, session, redirect, url_for, current_app, flash, request, current_app
from flask_login import login_required, current_user

from .. import db
from ..models import User, Role, Permission
from ..email import send_email
from . import main
from .forms import NameForm, EditProfileForm, EditProfileAdminForm
from ..decorators import admin_required


# HERE WE DEFINE A VIEW FUNCTION FOR THE INDEX

# ---** THIS INDEX IS FOR A INDEX IN THE FIRST PART OF THE COURSE **---


@main.route('/', methods=['GET', 'POST'])  # WE USE THE ROUTE METHOD FROM THE MAIN BLUEPRINT
def index():
    form = NameForm()  # ASSIGN THE FORM
    if form.validate_on_submit():  # IF THERE ARE INFORMATION ON THE FORM
        user = User.query.filter_by(username=form.name.data).first()  # SEARCH FOR THE USERNAME IN THE DB
        if user is None:  # IF THERE IS NOT, WE CREATE A NEW USER
            user = User(username=form.name.data)
            db.session.add(user)
            session['know'] = False
            if current_app.config['APP_ADMIN']:  # WE ASSERT THAT THE APP ADMIN IS TOOK
                send_email(current_app.config['APP_ADMIN'], 'New User', 'mail/new_user', user=user)  # WE SEND A EMAIL
        else:
            session['know'] = True
        session['name'] = form.name.data
        return redirect(url_for('.index'))  # WE USE .INDEX CAUSE THIS MAKE REFERENCE FOR MAIN.
        # INDEX TO USE THE BLUEPRINT
    return render_template('index.html',
                           form=form, name=session.get('name'),
                           know=session.get('know', False))


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        db.session.add(user)
        flash('Your profile has been updated')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    return render_template('edit_profile.html', form=form, user=user)
