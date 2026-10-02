from getpass import getpass

from werkzeug.security import generate_password_hash

from app import app, db, User


def create_or_update_admin():

    print()
    print("=" * 55)
    print("          FIREWALL LAB ADMIN SETUP")
    print("=" * 55)
    print()

    username = input(
        "Enter admin username: "
    ).strip()

    if not username:

        print()
        print("Username cannot be empty.")
        return


    password = getpass(
        "Enter admin password: "
    )


    if not password:

        print()
        print("Password cannot be empty.")
        return


    confirm_password = getpass(
        "Confirm admin password: "
    )


    if password != confirm_password:

        print()
        print("Passwords do not match.")
        return


    with app.app_context():

        user = User.query.filter_by(
            username=username
        ).first()


        # ----------------------------------------------------
        # UPDATE EXISTING USER
        # ----------------------------------------------------

        if user:

            user.password_hash = (
                generate_password_hash(
                    password
                )
            )

            user.role = "admin"

            user.active = True

            db.session.commit()

            print()
            print(
                "Existing admin account updated successfully."
            )


        # ----------------------------------------------------
        # CREATE NEW USER
        # ----------------------------------------------------

        else:

            new_admin = User(

                username=username,

                password_hash=(
                    generate_password_hash(
                        password
                    )
                ),

                role="admin",

                active=True
            )

            db.session.add(
                new_admin
            )

            db.session.commit()

            print()
            print(
                "New admin account created successfully."
            )


    print()
    print("=" * 55)
    print("             ADMIN SETUP COMPLETE")
    print("=" * 55)
    print(
        "Username:",
        username
    )
    print("=" * 55)
    print()


if __name__ == "__main__":

    create_or_update_admin()