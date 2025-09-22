from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken


class Command(BaseCommand):
    help = 'Clean up expired blacklisted tokens and outstanding tokens'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to keep expired tokens before deletion (default: 7)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        days = options['days']
        dry_run = options['dry_run']
        cutoff_date = timezone.now() - timedelta(days=days)

        self.stdout.write(
            self.style.SUCCESS(f'Cleaning up tokens older than {days} days (cutoff: {cutoff_date})')
        )

        # Clean up blacklisted tokens that have expired
        expired_blacklisted_tokens = BlacklistedToken.objects.filter(
            token__expires_at__lt=cutoff_date
        )

        blacklisted_count = expired_blacklisted_tokens.count()

        # Clean up outstanding tokens that are expired and not blacklisted
        expired_outstanding_tokens = OutstandingToken.objects.filter(
            expires_at__lt=cutoff_date
        ).exclude(
            id__in=BlacklistedToken.objects.values_list('token_id', flat=True)
        )

        outstanding_count = expired_outstanding_tokens.count()

        # Show statistics
        self.stdout.write(f'Found {blacklisted_count} expired blacklisted tokens')
        self.stdout.write(f'Found {outstanding_count} expired outstanding tokens')

        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN: No tokens will be deleted')
            )
            return

        # Perform the cleanup
        if blacklisted_count > 0:
            expired_blacklisted_tokens.delete()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {blacklisted_count} expired blacklisted tokens')
            )

        if outstanding_count > 0:
            expired_outstanding_tokens.delete()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {outstanding_count} expired outstanding tokens')
            )

        total_deleted = blacklisted_count + outstanding_count
        self.stdout.write(
            self.style.SUCCESS(f'Total tokens cleaned up: {total_deleted}')
        )
