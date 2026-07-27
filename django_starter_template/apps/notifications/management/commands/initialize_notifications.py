"""
Management command to initialize the notifications system with templates, events, 
and configurations. This command should be run after migrations to set up the 
notification infrastructure.
"""

from django.core.management.base import BaseCommand
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from apps.notifications.models import (
    NotificationTemplate,
    NotificationEvent,
    NotificationPreference,
)
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = "Initialize notification system with templates, events, and configurations"

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Reset existing templates and events (caution: destructive)",
        )
        parser.add_argument(
            "--init-prefs",
            action="store_true",
            help="Initialize notification preferences for existing users",
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.WARNING("=" * 70)
        )
        self.stdout.write(
            self.style.WARNING("  NOTIFICATION SYSTEM INITIALIZATION")
        )
        self.stdout.write(
            self.style.WARNING("=" * 70)
        )
        self.stdout.write("")

        reset = options.get("reset", False)
        init_prefs = options.get("init_prefs", False)

        if reset:
            self.stdout.write(
                self.style.WARNING(
                    "⚠️  Reset mode enabled - Existing data will be deleted!"
                )
            )
            confirm = input("Are you sure? Type 'yes' to continue: ")
            if confirm.lower() != "yes":
                self.stdout.write(self.style.ERROR("Operation cancelled."))
                return

            # Delete existing data
            NotificationEvent.objects.all().delete()
            NotificationTemplate.objects.all().delete()
            self.stdout.write(
                self.style.SUCCESS("✓ Cleaned existing templates and events")
            )

        # Step 1: Create notification templates
        self.stdout.write("\n📧 Creating notification templates...")
        templates_created = self._create_templates()
        self.stdout.write(
            self.style.SUCCESS(f"✓ Created/Updated {templates_created} templates")
        )

        # Step 2: Create notification events
        self.stdout.write("\n🔔 Creating notification events...")
        events_created = self._create_events()
        self.stdout.write(
            self.style.SUCCESS(f"✓ Created/Updated {events_created} events")
        )

        # Step 3: Link templates to events
        self.stdout.write("\n🔗 Linking templates to events...")
        links_created = self._link_templates_to_events()
        self.stdout.write(
            self.style.SUCCESS(f"✓ Created {links_created} template-event links")
        )

        # Step 4: Initialize user preferences
        if init_prefs:
            self.stdout.write("\n👤 Initializing user notification preferences...")
            prefs_created = self._initialize_user_preferences()
            self.stdout.write(
                self.style.SUCCESS(f"✓ Created preferences for {prefs_created} users")
            )

        # Summary
        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS("=" * 70)
        )
        self.stdout.write(
            self.style.SUCCESS("  ✅ NOTIFICATION SYSTEM INITIALIZED SUCCESSFULLY")
        )
        self.stdout.write(
            self.style.SUCCESS("=" * 70)
        )
        self.stdout.write("")
        self.stdout.write("Next steps:")
        self.stdout.write("  1. Review templates in Django Admin")
        self.stdout.write("  2. Customize email templates as needed")
        self.stdout.write("  3. Configure SMTP settings in your settings file")
        self.stdout.write("  4. Test notifications with: python manage.py shell")
        self.stdout.write("")

    def _create_templates(self):
        """Create notification templates"""
        templates_data = [
            # === USER ACCOUNT TEMPLATES ===
            {
                "name": "User Welcome Complete",
                "template_type": NotificationTemplate.TYPE_EMAIL,
                "subject": "Welcome to {{ platform_name }} - Account Setup Required",
                "body": """<h2>Welcome, {{ user_name }}! 👋</h2>

<p>Thank you for joining <strong>{{ platform_name }}</strong>! Your account has been created successfully.</p>

<!-- Account Information Section -->
<div style="background-color: #e8f4f8; border-left: 4px solid #0891b2; padding: 20px; border-radius: 6px; margin: 20px 0;">
    <h3 style="color: #0891b2; margin-top: 0;">📋 Your Account Information</h3>
    <table style="width: 100%; border-collapse: collapse;">
        <tr style="border-bottom: 1px solid #d0e8f2;">
            <td style="padding: 8px 0; font-weight: 500; color: #0891b2; width: 35%;">User ID:</td>
            <td style="padding: 8px 0; color: #333;">{{ user_id }}</td>
        </tr>
        <tr style="border-bottom: 1px solid #d0e8f2;">
            <td style="padding: 8px 0; font-weight: 500; color: #0891b2;">Email:</td>
            <td style="padding: 8px 0; color: #333;">{{ email }}</td>
        </tr>
        <tr style="border-bottom: 1px solid #d0e8f2;">
            <td style="padding: 8px 0; font-weight: 500; color: #0891b2;">Role:</td>
            <td style="padding: 8px 0; color: #333;"><strong>{{ role }}</strong></td>
        </tr>
    </table>
</div>

<!-- Critical Action Section -->
<div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 20px; border-radius: 8px; margin: 20px 0; color: white;">
    <h3 style="color: white; margin-top: 0; margin-bottom: 15px;">🔐 Step 1: Set Your Password</h3>
    <p style="margin: 10px 0;">Your account requires a password before you can log in. Click the button below to set your password:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="{{ reset_link }}" style="display: inline-block; padding: 14px 30px; background-color: white; color: #dc2626; text-decoration: none; border-radius: 6px; font-weight: 700; text-align: center; font-size: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
            SET YOUR PASSWORD
        </a>
    </div>
    <p style="margin: 10px 0; font-size: 13px; opacity: 0.95;">
        <strong>⏱️ This link expires in {{ expiry_hours }} hours</strong>
    </p>
</div>

<!-- Role Information Section -->
<div style="background-color: #f0f9ff; border-left: 4px solid #1e3c72; padding: 20px; border-radius: 6px; margin: 20px 0;">
    <h3 style="color: #1e3c72; margin-top: 0;">📚 About Your Role: {{ role }}</h3>
    <p>{{ role_description }}</p>
</div>

<!-- Getting Started Guide -->
<div style="background-color: #f0fdf4; border-left: 4px solid #16a34a; padding: 20px; border-radius: 6px; margin: 20px 0;">
    <h3 style="color: #16a34a; margin-top: 0;">🚀 Getting Started Steps</h3>
    <p><strong>Step 1:</strong> Set your password using the link above ✓</p>
    <p><strong>Step 2:</strong> Log in to your account using your email and new password</p>
    <p><strong>Step 3:</strong> Complete your profile information</p>
</div>

<!-- Support Information Section -->
<div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 20px; border-radius: 6px; margin: 20px 0;">
    <h3 style="color: #d97706; margin-top: 0;">🆘 Need Help?</h3>
    <p>If you encounter any issues or have questions about using {{ platform_name }}, please reach out:</p>
    <p><strong>Email:</strong> <a href="mailto:{{ support_email }}" style="color: #2a5298; text-decoration: none;">{{ support_email }}</a></p>
</div>""",
                "variables": {
                    "user_name": "string",
                    "user_id": "string",
                    "email": "string",
                    "role": "string",
                    "role_description": "string",
                    "reset_link": "string",
                    "expiry_hours": "number",
                    "platform_name": "string",
                    "support_email": "string",
                },
                "priority": NotificationTemplate.PRIORITY_HIGH,
                "description": "Consolidated welcome email for new users with account details, role info, and password setup link",
            },
            # Backwards-compatible account fallback templates (used by NotificationService.send_account_notification)
            {
                "name": "accounts.welcome",
                "template_type": NotificationTemplate.TYPE_EMAIL,
                "subject": "Welcome to {{ platform_name }}",
                "body": "Dear {{ user_name }},\n\nWelcome to {{ platform_name }}! Your account has been created.\n\nBest regards,\n{{ platform_name }} Team",
                "variables": {"user_name": "string", "platform_name": "string"},
                "priority": NotificationTemplate.PRIORITY_MEDIUM,
                "description": "Fallback welcome email for accounts module",
            },
            {
                "name": "accounts.account_activated",
                "template_type": NotificationTemplate.TYPE_EMAIL,
                "subject": "Your Account Has Been Activated",
                "body": "Dear {{ user_name }},\n\nYour account has been activated and you can now log in at {{ login_url }}.\n\nBest regards,\n{{ platform_name }} Team",
                "variables": {"user_name": "string", "login_url": "string"},
                "priority": NotificationTemplate.PRIORITY_MEDIUM,
                "description": "Fallback account activation email",
            },
            {
                "name": "accounts.role_changed",
                "template_type": NotificationTemplate.TYPE_IN_APP,
                "subject": "Role Updated",
                "body": "Your role has been changed to {{ new_role }}.",
                "variables": {"new_role": "string"},
                "priority": NotificationTemplate.PRIORITY_MEDIUM,
                "description": "Fallback in-app notification for role changes",
            },
            {
                "name": "User Welcome Email",
                "template_type": NotificationTemplate.TYPE_EMAIL,
                "subject": "Welcome to {{ platform_name }}",
                "body": """Dear {{ user_name }},

Welcome to the {{ platform_name }}!

Your account has been successfully created with the following details:
• User ID: {{ user_id }}
• Email: {{ email }}
• Role: {{ role }}

You will receive a separate email with instructions to set your password.

If you have any questions, please contact your system administrator.

Best regards,
{{ platform_name }} Team""",
                "variables": {
                    "user_name": "string",
                    "user_id": "string",
                    "email": "string",
                    "role": "string",
                },
                "priority": NotificationTemplate.PRIORITY_HIGH,
                "description": "Welcome email sent to new users",
            },
            {
                "name": "User Welcome In-App",
                "template_type": NotificationTemplate.TYPE_IN_APP,
                "subject": "Welcome!",
                "body": "Welcome to {{ platform_name }}, {{ user_name }}! Your account has been created successfully.",
                "variables": {"user_name": "string"},
                "priority": NotificationTemplate.PRIORITY_MEDIUM,
                "description": "In-app welcome notification",
            },
            {
                "name": "Password Reset Required",
                "template_type": NotificationTemplate.TYPE_EMAIL,
                "subject": "Set Your Password - {{ platform_name }}",
                "body": """Dear {{ user_name }},

Your account has been created by an administrator. You need to set your password to access the system.

Please click the link below to set your password:
{{ reset_link }}

This link will expire in {{ expiry_hours }} hours.

If you did not request this account, please contact your system administrator immediately.

Best regards,
{{ platform_name }} Team""",
                "variables": {
                    "user_name": "string",
                    "reset_link": "string",
                    "expiry_hours": "number",
                },
                "priority": NotificationTemplate.PRIORITY_HIGH,
                "description": "Password reset notification for new users",
            },
            {
                "name": "Role Changed",
                "template_type": NotificationTemplate.TYPE_IN_APP,
                "subject": "Your Role Has Been Changed",
                "body": "Your role has been changed from {{ old_role }} to {{ new_role }} by {{ changed_by }}.",
                "variables": {
                    "old_role": "string",
                    "new_role": "string",
                    "changed_by": "string",
                },
                "priority": NotificationTemplate.PRIORITY_HIGH,
                "description": "Notification when user role is changed",
            },
            {
                "name": "User Approved",
                "template_type": NotificationTemplate.TYPE_EMAIL,
                "subject": "Your Account Has Been Approved",
                "body": """Dear {{ user_name }},

Your account has been approved by {{ approved_by }}.

You can now access all features available for your role: {{ role }}.

Login at: {{ login_url }}

Best regards,
{{ platform_name }} Team""",
                "variables": {
                    "user_name": "string",
                    "approved_by": "string",
                    "role": "string",
                    "login_url": "string",
                },
                "priority": NotificationTemplate.PRIORITY_MEDIUM,
                "description": "User account approval notification",
            },
         
        ]

        count = 0
        for template_data in templates_data:
            template, created = NotificationTemplate.objects.update_or_create(
                name=template_data["name"], defaults=template_data
            )
            if created:
                self.stdout.write(
                    f"  ✓ Created: {template.name} ({template.template_type})"
                )
            else:
                self.stdout.write(
                    f"  ↻ Updated: {template.name} ({template.template_type})"
                )
            count += 1

        return count

    def _create_events(self):
        """Create notification events"""
        # Define new event types
        EVENT_USER_CREATED = "user_created"
        EVENT_USER_APPROVED = "user_approved"
        EVENT_ROLE_CHANGED = "role_changed"

        events_data = [
            # User events
            {
                "event_type": EVENT_USER_CREATED,
                "name": "User Created",
                "description": "Triggered when a new user account is created",
                "is_active": True,
            },
            {
                "event_type": EVENT_USER_APPROVED,
                "name": "User Approved",
                "description": "Triggered when a user account is approved",
                "is_active": True,
            },
            {
                "event_type": EVENT_ROLE_CHANGED,
                "name": "Role Changed",
                "description": "Triggered when a user's role is changed",
                "is_active": True,
            },
        ]


        count = 0
        for event_data in events_data:
            event, created = NotificationEvent.objects.update_or_create(
                event_type=event_data["event_type"], defaults=event_data
            )
            if created:
                self.stdout.write(f"  ✓ Created: {event.name}")
            else:
                self.stdout.write(f"  ↻ Updated: {event.name}")
            count += 1

        return count

    def _link_templates_to_events(self):
        """Link templates to events"""
        links = [
            # User events
            ("user_created", "User Welcome In-App", "in_app"),
            ("user_created", "User Welcome Email", "email"),
            ("user_approved", "User Approved", "email"),
            ("role_changed", "Role Changed", "in_app"),
        ]

        count = 0
        for event_type, template_name, channel in links:
            try:
                event = NotificationEvent.objects.get(event_type=event_type)
                template = NotificationTemplate.objects.get(name=template_name)

                if channel == "email":
                    event.default_email_template = template
                elif channel == "sms":
                    event.default_sms_template = template
                elif channel == "push":
                    event.default_push_template = template
                elif channel == "in_app":
                    event.default_in_app_template = template

                event.save()
                self.stdout.write(
                    f"  ✓ Linked: {event.name} → {template.name} ({channel})"
                )
                count += 1
            except (NotificationEvent.DoesNotExist, NotificationTemplate.DoesNotExist) as e:
                self.stdout.write(
                    self.style.WARNING(
                        f"  ⚠ Could not link {event_type} to {template_name}: {str(e)}"
                    )
                )

        return count

    def _initialize_user_preferences(self):
        """Initialize notification preferences for existing users"""
        users_without_prefs = User.objects.filter(
            notification_preferences__isnull=True
        )

        count = 0
        for user in users_without_prefs:
            NotificationPreference.objects.create(
                user=user,
                email_enabled=True,
                sms_enabled=False,
                push_enabled=True,
                in_app_enabled=True,
                email_address=user.email,
            )
            count += 1

        return count
