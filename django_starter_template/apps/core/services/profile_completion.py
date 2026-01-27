"""
Profile Completion Service

Handles the complete user profile setup flow including:
1. Personal information validation
2. Profile image upload and quality check
3. Facial enrollment with duplicate detection
4. Geolocation permission setup
5. Profile completion confirmation
"""

import logging
from typing import Tuple, Dict, Any, Optional
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()
logger = logging.getLogger(__name__)


class ProfileCompletionService:
    """
    Service for completing user profiles with facial enrollment.
    
    Steps:
    1. Update basic profile info
    2. Upload and validate profile image
    3. Enroll face (extract embedding, check quality, detect duplicates)
    4. Store face enrollment
    5. Mark profile as complete
    """

    @staticmethod
    def complete_profile(
        user: User,
        profile_data: Dict[str, Any],
        profile_image=None,
        facial_image=None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Complete user profile with all required information.

        Args:
            user: User instance to complete profile for
            profile_data: Dictionary with profile fields:
                - phone_number
                - date_of_birth
                - address
                - city
                - country
                - etc.
            profile_image: Profile image file (for display and recognition)
            facial_image: Facial image file (for recognition) - if None, uses profile_image

        Returns:
            Tuple[bool, Dict]:
                - bool: Success status
                - Dict: Completion details including face enrollment info
        """
        try:
            from logx.attendance.utils.facial_verification import (
                FacialVerificationService,
            )
            from logx.attendance.utils.face_deduplication import (
                FaceDuplicateDetector,
            )

            completion_details = {
                "profile_updated": False,
                "image_uploaded": False,
                "face_enrolled": False,
                "duplicate_check": {"is_duplicate": False, "matches": []},
                "warnings": [],
                "errors": [],
            }

            # Step 1: Update basic profile information
            try:
                if profile_data:
                    # Update user profile fields
                    for key, value in profile_data.items():
                        if hasattr(user, key) and key not in [
                            "id",
                            "password",
                            "email",
                            "username",
                        ]:
                            setattr(user, key, value)
                    user.save()
                    completion_details["profile_updated"] = True
                    logger.info(f"Profile updated for user {user.id}")
            except Exception as e:
                completion_details["errors"].append(f"Profile update failed: {str(e)}")
                logger.error(f"Profile update error: {str(e)}")
                return False, completion_details

            # Step 2: Upload profile image (if provided)
            if profile_image:
                try:
                    user.profile_image = profile_image
                    user.save()
                    completion_details["image_uploaded"] = True
                    logger.info(f"Profile image uploaded for user {user.id}")
                except Exception as e:
                    completion_details["errors"].append(
                        f"Profile image upload failed: {str(e)}"
                    )
                    logger.error(f"Image upload error: {str(e)}")

            # Step 3: Enroll face (use facial_image if provided, otherwise use profile_image)
            image_to_enroll = facial_image if facial_image else profile_image
            
            if image_to_enroll:
                try:
                    # Extract face embedding
                    embedding = FacialVerificationService.extract_face_embedding(
                        image_to_enroll
                    )

                    if embedding is None:
                        completion_details["errors"].append(
                            "No face detected in the provided image. "
                            "Please ensure your face is clearly visible."
                        )
                        return False, completion_details

                    # Check face quality
                    quality_score, quality_msg = (
                        FacialVerificationService.get_face_quality_score(image_to_enroll)
                    )

                    if quality_score is None or quality_score < 0.6:
                        completion_details["errors"].append(
                            f"Face quality too low: {quality_msg}. "
                            "Please retake with better lighting and clear frontal face."
                        )
                        return False, completion_details

                    completion_details["face_quality"] = {
                        "score": float(quality_score),
                        "label": "Good"
                        if quality_score >= 0.7
                        else "Acceptable"
                        if quality_score >= 0.6
                        else "Poor",
                    }

                    # Step 4: Check for duplicate faces
                    logger.info(f"Checking for duplicate faces for user {user.id}")
                    is_duplicate, matches = FaceDuplicateDetector.check_duplicate(
                        embedding,
                        exclude_user_id=user.id,
                        return_matches=True,
                    )

                    completion_details["duplicate_check"] = {
                        "is_duplicate": is_duplicate,
                        "matches": matches,
                    }

                    if is_duplicate:
                        # Return with duplicate warning but allow override
                        completion_details["warnings"].append(
                            f"Face similar to {len(matches)} existing enrollment(s). "
                            "Please verify this is your own face."
                        )
                        logger.warning(
                            f"Duplicate faces detected for user {user.id}: "
                            f"{len(matches)} matches"
                        )

                    # Step 5: Store face data directly on User model
                    user.embedding_vector = embedding.tobytes()
                    user.embedding_hash = FaceDuplicateDetector._generate_lsh_hash(
                        embedding, FaceDuplicateDetector._get_lsh_vectors()
                    )
                    user.face_quality_score = float(quality_score)
                    user.face_confidence_score = 1.0  # Default confidence
                    user.face_enrolled_at = timezone.now()
                    user.face_enrollment_verified = True
                    user.save()

                    completion_details["face_enrolled"] = True
                    logger.info(
                        f"Face enrolled for user {user.id}"
                    )

                except Exception as e:
                    completion_details["errors"].append(
                        f"Face enrollment failed: {str(e)}"
                    )
                    logger.error(f"Face enrollment error: {str(e)}")
                    return False, completion_details

            # Step 6: Mark profile as complete
            try:
                user.profile_complete = True
                user.profile_completed_at = timezone.now()
                user.save()
                completion_details["profile_complete"] = True
                logger.info(f"Profile marked as complete for user {user.id}")
            except Exception as e:
                completion_details["warnings"].append(
                    f"Could not mark profile as complete: {str(e)}"
                )
                logger.warning(f"Profile completion flag error: {str(e)}")

            return True, completion_details

        except Exception as e:
            logger.error(f"Unexpected error in profile completion: {str(e)}")
            return False, {
                "errors": [f"Profile completion failed: {str(e)}"],
                "profile_updated": False,
                "image_uploaded": False,
                "face_enrolled": False,
            }

    @staticmethod
    def validate_profile_completeness(user: User) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if a user's profile is complete and ready for use.

        Args:
            user: User instance to check

        Returns:
            Tuple[bool, Dict]:
                - bool: True if profile is complete
                - Dict: Details of what's missing or incomplete
        """
        completeness = {
            "is_complete": True,
            "missing_fields": [],
            "warnings": [],
        }

        # Check required fields
        required_fields = [
            "first_name",
            "last_name",
            "email",
            "profile_image",
        ]

        for field in required_fields:
            if not getattr(user, field, None):
                completeness["missing_fields"].append(field)
                completeness["is_complete"] = False

        # Check face enrollment
        if not user.has_face_enrolled():
            completeness["missing_fields"].append("face_enrollment")
            completeness["is_complete"] = False
        else:
            if not user.face_enrollment_verified:
                completeness["warnings"].append("Face enrollment not verified")

        # Check if explicitly marked complete
        if hasattr(user, "profile_complete") and not user.profile_complete:
            completeness["is_complete"] = False
            completeness["warnings"].append(
                "Profile not marked as complete by user"
            )

        return completeness["is_complete"], completeness

    @staticmethod
    def suggest_profile_improvements(user: User) -> Dict[str, Any]:
        """
        Suggest improvements to user's profile.

        Args:
            user: User instance

        Returns:
            Dict with improvement suggestions
        """
        suggestions = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
        }

        # Check profile image quality
        if user.profile_image:
            suggestions["low_priority"].append(
                {
                    "title": "Profile Photo Clarity",
                    "description": "Ensure your profile photo clearly shows your face",
                    "action": "Re-upload profile photo if needed",
                }
            )

        # Check face enrollment freshness
        if user.has_face_enrolled():
            days_old = user.days_since_face_enrollment

            if days_old > 180:
                suggestions["low_priority"].append(
                    {
                        "title": "Update Face Enrollment",
                        "description": "Your facial recognition data is older than 6 months",
                        "action": "Re-enroll your face with a recent photo",
                    }
                )
        else:
            suggestions["high_priority"].append(
                {
                    "title": "Facial Enrollment Missing",
                    "description": "Complete facial enrollment for attendance signing",
                    "action": "Enroll your face in profile settings",
                }
            )

        return suggestions


class FirstLoginFlow:
    """
    Handles the first login experience for new users.
    
    Forces users through required setup steps:
    1. Password change (if temp password)
    2. Profile completion
    3. Face enrollment
    4. Terms acceptance
    """

    @staticmethod
    def check_setup_required(user: User) -> Dict[str, bool]:
        """
        Check which setup steps are required for this user.

        Returns:
            Dict mapping setup step to whether it's required
        """
        setup_required = {
            "change_password": getattr(user, "is_temp_password", False),
            "complete_profile": not getattr(user, "profile_complete", False),
            "enroll_face": not user.has_face_enrolled(),
            "accept_terms": not getattr(user, "terms_accepted", False),
        }

        return setup_required

    @staticmethod
    def mark_step_complete(user: User, step: str) -> bool:
        """
        Mark a setup step as complete.

        Args:
            user: User instance
            step: Step name ('change_password', 'complete_profile', 'enroll_face', 'accept_terms')

        Returns:
            bool: Success status
        """
        try:
            if step == "change_password":
                user.is_temp_password = False
            elif step == "complete_profile":
                user.profile_complete = True
            elif step == "accept_terms":
                user.terms_accepted = True

            user.save()
            return True
        except Exception as e:
            logger.error(f"Error marking {step} as complete: {str(e)}")
            return False
