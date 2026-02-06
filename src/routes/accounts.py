from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from config import get_jwt_auth_manager, get_settings
from config.settings import BaseAppSettings
from database import get_db
from database.models.accounts import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
)
from schemas.accounts import (
    AccessTokenResponseSchema,
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    RefreshTokenRequestSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import PasswordManager


router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])


def _is_expired(expires_at: datetime) -> bool:
    # SQLite може повертати naive datetime → робимо tz-aware (як в підказках проєкту)
    expires_utc = cast(datetime, expires_at).replace(tzinfo=timezone.utc)
    return expires_utc <= datetime.now(timezone.utc)


def _get_default_user_group(db: Session) -> UserGroupModel:
    group = (
        db.query(UserGroupModel)
        .filter(UserGroupModel.name == UserGroupEnum.USER)
        .first()
    )
    if group is None:
        raise HTTPException(status_code=500, detail="Default user group not found.")
    return group


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_data: UserRegistrationRequestSchema,
    db: Session = Depends(get_db),
):
    exists = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group = _get_default_user_group(db)
        hashed_password = PasswordManager.hash_password(user_data.password)

        user = UserModel(
            email=user_data.email,
            hashed_password=hashed_password,
            is_active=False,
            group_id=cast(int, group.id),
        )
        db.add(user)
        db.flush()  # щоб з’явився user.id

        activation = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation)

        db.commit()
        db.refresh(user)

        return UserRegistrationResponseSchema(id=cast(int, user.id), email=user.email)

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
def activate_account(
    payload: UserActivationRequestSchema,
    db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter(UserModel.email == payload.email).first()
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if cast(bool, user.is_active):
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_rec = (
        db.query(ActivationTokenModel)
        .filter(ActivationTokenModel.user_id == cast(int, user.id))
        .first()
    )
    if (
        token_rec is None
        or token_rec.token != payload.token
        or _is_expired(cast(datetime, token_rec.expires_at))
    ):
        if token_rec is not None and _is_expired(cast(datetime, token_rec.expires_at)):
            db.delete(token_rec)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    db.delete(token_rec)
    db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
def password_reset_request(
    payload: PasswordResetRequestSchema,
    db: Session = Depends(get_db),
):
    # завжди повертаємо success message щоб не "зливати" інформацію
    user = db.query(UserModel).filter(UserModel.email == payload.email).first()

    if user is not None and cast(bool, user.is_active):
        try:
            db.query(PasswordResetTokenModel).filter(
                PasswordResetTokenModel.user_id == cast(int, user.id)
            ).delete()

            reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
            db.add(reset_token)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            # відповідь все одно та сама
            pass

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
def password_reset_complete(
    payload: PasswordResetCompleteRequestSchema,
    db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter(UserModel.email == payload.email).first()
    if user is None or not cast(bool, user.is_active):
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_rec = (
        db.query(PasswordResetTokenModel)
        .filter(PasswordResetTokenModel.user_id == cast(int, user.id))
        .first()
    )

    if (
        token_rec is None
        or token_rec.token != payload.token
        or _is_expired(cast(datetime, token_rec.expires_at))
    ):
        if token_rec is not None:
            db.delete(token_rec)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.hashed_password = PasswordManager.hash_password(payload.password)
        db.delete(token_rec)
        db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=UserLoginResponseSchema)
def login(
    payload: UserLoginRequestSchema,
    db: Session = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user = db.query(UserModel).filter(UserModel.email == payload.email).first()
    if user is None or not PasswordManager.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not cast(bool, user.is_active):
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token(
            user_id=cast(int, user.id),
            days=cast(int, settings.LOGIN_TIME_DAYS),
        )
        refresh_token = jwt_manager.create_refresh_token(
            user_id=cast(int, user.id),
            days=cast(int, settings.REFRESH_TIME_DAYS),
        )

        refresh_rec = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            token=refresh_token,
            days=cast(int, settings.REFRESH_TIME_DAYS),
        )
        db.add(refresh_rec)
        db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/", response_model=AccessTokenResponseSchema)
def refresh_access_token(
    payload: RefreshTokenRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        decoded = jwt_manager.decode_refresh_token(payload.refresh_token)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    user_id = decoded.get("user_id") if isinstance(decoded, dict) else None
    if user_id is None:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    token_rec = db.query(RefreshTokenModel).filter(
        RefreshTokenModel.token == payload.refresh_token
    ).first()
    if token_rec is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = db.query(UserModel).filter(UserModel.id == cast(int, user_id)).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access = jwt_manager.create_access_token(
        user_id=cast(int, user.id),
        days=cast(int, settings.LOGIN_TIME_DAYS),
    )
    return AccessTokenResponseSchema(access_token=new_access)
