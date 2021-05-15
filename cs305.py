# -*- coding: utf-8 -*-
"""

:Authors: Balwinder Sodhi
"""
import csv
import json
import logging
import random
import string
from sqlite3 import DatabaseError
from typing import Iterable
from zipfile import ZipFile

from passlib.hash import pbkdf2_sha256

B64_HDR = "data:image/jpeg;base64,"


class CS305Exception(Exception):
    pass


class User(object):
    user_id = 0
    login_id = None
    password_hashed = None
    first_name = None
    last_name = None
    is_locked = False
    role = "GN"


class KnownFace(object):
    kf_id = 0
    user = None
    face_enc = None
    photo = None


def random_str(size=10) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))


def make_nav(nav_file, role_code) -> dict:
    """
    The nav_file contains JSON data of the format:
    [
        {
            "label": "Known Faces", "href": "#/kf.find",
            "roles": "SU,ST", "menu": "Manage Users"
        },
        {
            "label": "Admin", "href": "#/admin",
            "roles": "SU", "menu": "Admin"
        },
        ...
        ...
    ]
    :param nav_file: Path of the JSON file
    :param role_code: A string from {"SU", "ST", "GE", "*"}
    :return:
    """
    try:
        with open(nav_file, "r") as nd:
            nav = json.load(nd)
            links = []
            menus = {}
            for n in nav:
                r = n.pop("roles")
                if "-{}".format(role_code) in r:
                    continue

                if "*" in r or role_code in r:
                    m = n.pop("menu")
                    if m:
                        if m not in menus:
                            menus[m] = []
                        menus[m].append(n)
                    else:
                        links.append(n)

            return {"menus": menus, "links": links}

    except Exception as ex:
        logging.exception("Error occurred when loading nav data.")


def error_json(obj) -> dict:
    return {"status": "ERROR", "body": obj}


def ok_json(obj) -> dict:
    return {"status": "OK", "body": obj}


def make_random_user() -> User:
    u = User()
    u.user_id = random.randint(1, 5000)
    u.role = random.choice(["SU", "ST", "GN"])
    u.is_locked = random.choice([True, False])
    u.login_id = random_str(6)
    u.first_name = random.choice(["Amar", "Vimal", "Kamal", "Jay"])
    u.last_name = random.choice(["Singh", "Roy", "Gupta", "Dass"])
    u.password_hashed = pbkdf2_sha256.hash(u.first_name)
    return u


def make_random_face() -> KnownFace:
    kf = KnownFace()
    kf.kf_id = random.randint(1, 3899)
    kf.user = make_random_user()
    kf.photo = B64_HDR + random_str(500)
    kf.face_enc = kf.photo[-10:]
    return kf


def _encode_and_save_photo(login_id: str, photo: str):
    logging.debug("Fake encoded and saving photo for login {}".format(login_id))


def process_photos_zip(zip_file_path: str) -> int:
    """
    Processes the .jpg files contained in the supplied ZIP file.
    Names of .jpg files are expected to be in the format:
    [login ID].jpg
    :param zip_file_path: Path of the input ZIP file.
    :return: Number of .jpg files successfully processed.
    """
    processed_count = 0
    try:
        with ZipFile(zip_file_path) as myzip:
            zitems = [x for x in myzip.namelist()
                      if x.lower().endswith(".jpg") and "MACOSX" not in x]
            logging.debug("ZIP file {0} contains {1} items.".format(
                zip_file_path, len(zitems)))
            for zn in zitems:
                try:
                    logging.debug("Extracting JPG from ZIP entry: " + str(zn))
                    with myzip.open(zn) as zf:
                        logging.debug("Processing ZIP entry: {}".format(zn))
                        photo = zf.read()
                        if not photo:
                            logging.warning(
                                "Photo not found in ZIP entry: {}".format(zn))
                            continue
                        # login_id.jpg
                        login_id = zn.split(".")[0]
                        _encode_and_save_photo(login_id, photo)
                        processed_count += 1
                except Exception as ex:
                    logging.exception("Error when processing photo. " + str(ex))

    except Exception as ex:
        logging.exception("Error when processing ZIP file. " + str(ex))
    return processed_count


def get_face_encoding_b64(photo_b64: str) -> str:
    # Faking it up. Just return the first 10 chars
    return photo_b64[-10:]


class CS305App:

    def __init__(self, users: Iterable[User], faces: Iterable[KnownFace], nav_file: str):
        """

        :param users: List of initial User instances to work with.
        :param faces: List of initial KnownFace instances to work with.
        :param nav_file: Path of the navigation structure JSON file.
                See :func:`~make_nav`
        """
        self.users = users
        self.faces = faces
        self.nav_file = nav_file

    def get_user_by_login_id(self, login_id: str) -> User:
        for u in self.users:
            if u.login_id == login_id:
                return u

    def login(self, login_id: str, plain_pass: str) -> dict:
        try:
            u = self.get_user_by_login_id(login_id)
            valid = False
            if u:
                if u.is_locked:
                    return error_json("User is locked! Please contact admin.")
                logging.info("Got user: {0}".format(u.login_id))
                valid = pbkdf2_sha256.verify(plain_pass, u.password_hashed)

            if not valid:
                return error_json("Invalid user/password.")
            else:
                nav = make_nav(self.nav_file, u.role)
                return ok_json({"user": u, "nav": nav})
        except Exception as ex:
            msg = "Error when authenticating."
            logging.exception(msg)
            return error_json(msg)

    def get_known_face_by_id(self, kf_id: int) -> KnownFace:
        for kf in self.faces:
            if kf.kf_id == kf_id:
                return kf

    def save_entity(self, obj: object) -> int:
        if isinstance(obj, User):
            u = self.get_user_by_login_id(obj.login_id)
            if u:
                self.users.remove(u)
            self.users.append(obj)
            rows_affected = 1
        elif isinstance(obj, KnownFace):
            kf = self.get_known_face_by_id(obj.kf_id)
            if kf:
                self.faces.remove(kf)
            self.faces.append(obj)
            rows_affected = 1
        else:
            raise DatabaseError("Unsupported entity type: " + type(obj))
        return rows_affected

    def kface_save(self, kf: KnownFace) -> dict:
        try:
            face_enc = None
            if kf.photo:
                if kf.photo.startswith(B64_HDR):
                    photo_b64 = kf.photo[len(B64_HDR):]
                    face_enc = get_face_encoding_b64(photo_b64)
                else:
                    raise Exception(
                        "Please supply a JPG format image. Mere renaming to .jpg won't work!")
            else:
                logging.debug("No photo supplied.")

            if kf.kf_id:
                kf2 = self.get_known_face_by_id(kf.kf_id)
                kf2.face_enc = face_enc
                self.save_entity(kf)
                logging.debug("Updated known face: {}".format(kf))
            else:
                try:
                    u = kf.user
                    rc = 0
                    if isinstance(u, User):
                        u.password_hashed = pbkdf2_sha256.hash(u.first_name)
                        rc += self.save_entity(u)
                    else:
                        raise CS305Exception("Expected a User object. Got: " + str(u))

                    rc += self.save_entity(kf)
                    if rc != 2:
                        raise CS305Exception("Could not save known face and user info. Please try again.")

                except DatabaseError as dbe:
                    raise dbe
                logging.info("Inserted: {}".format(kf))

            return ok_json(kf)

        except Exception as ex:
            msg = "Error when saving known face."
            logging.exception(msg)
            return error_json("{0}: {1}".format(msg, ex))

    def _save_row_data(self, row_data: dict):
        u = User()
        u.user_id = random.randint(1, 5000)
        u.role = row_data["role"]
        u.first_name = row_data["first_name"]
        u.last_name = row_data["last_name"]
        u.login_id = row_data["login_id"]
        u.password_hashed = pbkdf2_sha256.hash(u.first_name)
        u.is_locked = False
        self.save_entity(u)

    def users_upload(self, role: str, users_csv: str) -> dict:
        """
        The users CSV file contains rows of following values:
        role, first_name, last_name, login_id
        :param role:
        :param users_csv:
        :return: OK JSON response object when successful, else ERROR object.
        """
        try:
            # Only a superuser can add new users
            if "SU" != role:
                return error_json("Operation not allowed. Insufficient privileges!")

            if users_csv == '':
                return error_json("No file supplied!")

            with open(users_csv, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    self._save_row_data(row)

            return ok_json("Users added successfully!")

        except Exception as ex:
            msg = "Error when handling users upload request."
            logging.exception(msg)
            return error_json(msg)
