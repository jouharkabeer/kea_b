import os
import io
import uuid
import base64
import threading
import time
from functools import wraps
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import logging
from django.conf import settings
from django.core.mail import EmailMessage
from django.core.files.base import ContentFile
from django.http import HttpRequest, HttpResponse, FileResponse, JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
# ReportLab imports
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.platypus import Image as ReportLabImage
import qrcode
import qrcode.image.pil
import jwt
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

# Set up logger
logger = logging.getLogger(__name__)

def generate_user_qr_code(user):
    """
    Generate a simple, scannable QR code with user data.
    Uses KEA_QR format that's much shorter and more reliable.
    """
    try:
        # Get user data
        user_id = str(user.user_id)
        kea_id = user.kea_id
        
        # Get user name for logging
        first_name = getattr(user, "first_name", "")
        last_name = getattr(user, "last_name", "")
        user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
        
        logger.info(f"Generating simple QR code for user: {user_name} (KEA ID: {kea_id})")
        
        # Create simple QR data format that's easy to scan
        # Format: KEA_QR|USER_ID=uuid|KEA_ID=kea123|NAME=username
        qr_data_parts = [
            'KEA_QR',
            f'USER_ID={user_id}',
            f'KEA_ID={kea_id}',
            f'NAME={user_name[:20]}'  # Limit name length to keep QR small
        ]
        
        # Add expiry if available (optional, keeps QR smaller without it)
        if hasattr(user, 'membership_expiry') and user.membership_expiry:
            expiry_str = user.membership_expiry.strftime('%Y-%m-%d')
            qr_data_parts.append(f'EXPIRY={expiry_str}')
        
        # Join with pipe separator
        qr_data = '|'.join(qr_data_parts)
        
        logger.info(f"QR data: {qr_data}")
        logger.info(f"QR data length: {len(qr_data)} characters")
        
        # Generate QR code with optimal settings for readability
        qr = qrcode.QRCode(
            version=1,  # Start with smallest version
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Low error correction for more data
            box_size=10,  # Larger boxes for better scanning
            border=4,     # Standard border
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        logger.info(f"QR code version: {qr.version}")
        
        # Create QR code image with high contrast
        img = qr.make_image(
            image_factory=qrcode.image.pil.PilImage,
            fill_color="black",
            back_color="white"
        )
        
        # Resize to larger size for better scanning (300x300 instead of 200x200)
        img = img.resize((300, 300), Image.Resampling.LANCZOS)
        
        # Save QR code to buffer
        buffer = BytesIO()
        img.save(buffer, format="PNG", optimize=True, quality=95)
        buffer.seek(0)
        
        logger.info("Simple QR code generated successfully")
        return buffer
        
    except Exception as e:
        logger.error(f"Error generating simple QR code: {e}")
        
        # Fallback: Ultra-simple QR with just user_id
        try:
            logger.info("Generating fallback QR with just user_id")
            fallback_qr_data = f"KEA_QR|USER_ID={str(user.user_id)}"
            
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4
            )
            qr.add_data(fallback_qr_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img = img.resize((300, 300), Image.Resampling.LANCZOS)
            
            fallback_buffer = BytesIO()
            img.save(fallback_buffer, format="PNG")
            fallback_buffer.seek(0)
            return fallback_buffer
            
        except Exception as fallback_error:
            logger.error(f"Even fallback QR generation failed: {fallback_error}")
            
            # Absolute fallback - empty image
            empty_img = Image.new('RGB', (300, 300), color='lightgray')
            draw = ImageDraw.Draw(empty_img)
            draw.text((100, 140), "QR ERROR", fill='black')
            
            empty_buffer = BytesIO()
            empty_img.save(empty_buffer, format="PNG")
            empty_buffer.seek(0)
            return empty_buffer
def create_user_with_qr(user):
    """
    Create a QR code for the user and save it to their profile.
    """
    try:
        # Get user name for logging
        first_name = getattr(user, "first_name", "")
        last_name = getattr(user, "last_name", "")
        user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
        
        logger.info(f"Creating QR code for user: {user_name} (KEA ID: {user.kea_id})")
        qr_buffer = generate_user_qr_code(user)
        file_name = f"qr_{user.kea_id}.png"
        
        # Save the QR code to the user's profile
        user.qr_code.save(file_name, ContentFile(qr_buffer.getvalue()), save=True)
        logger.info(f"QR code saved successfully: {file_name}")
        
        return True
    except Exception as e:
        logger.error(f"Error creating user QR code: {e}")
        return False


def get_profile_image_for_pdf(user, request, size=(200, 200)):
    """
    Get user's profile image and convert it to BytesIO buffer for PDF use.
    Returns BytesIO buffer or None if no image available.
    """
    try:
        # Check if user has profile picture
        if hasattr(user, 'profile_picture') and user.profile_picture:
            # Get user name for logging
            first_name = getattr(user, "first_name", "")
            last_name = getattr(user, "last_name", "")
            user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
            
            logger.info(f"Found profile picture for user: {user_name} (KEA ID: {user.kea_id})")
            
            # Try to open the profile picture
            try:
                # Open the image file
                img = Image.open(user.profile_picture.path)
                
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'LA', 'P'):
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'P':
                        img = img.convert('RGBA')
                    background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = background
                
                # Resize to specified size while maintaining aspect ratio
                img.thumbnail(size, Image.Resampling.LANCZOS)
                
                # Create a square image with white background
                square_img = Image.new('RGB', size, (255, 255, 255))
                # Center the image
                offset = ((size[0] - img.size[0]) // 2, (size[1] - img.size[1]) // 2)
                square_img.paste(img, offset)
                
                # Convert to buffer
                img_buffer = BytesIO()
                square_img.save(img_buffer, format='PNG', optimize=True)
                img_buffer.seek(0)
                
                logger.info("Profile picture processed successfully")
                return img_buffer
                
            except Exception as e:
                logger.warning(f"Failed to process profile picture: {e}")
                return None
                
        elif hasattr(user, 'profile_image') and user.profile_image:
            # Alternative field name
            # Get user name for logging
            first_name = getattr(user, "first_name", "")
            last_name = getattr(user, "last_name", "")
            user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
            
            logger.info(f"Found profile image for user: {user_name} (KEA ID: {user.kea_id})")
            try:
                img = Image.open(user.profile_image.path)
                # Same processing as above
                if img.mode in ('RGBA', 'LA', 'P'):
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'P':
                        img = img.convert('RGBA')
                    background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = background
                
                img.thumbnail(size, Image.Resampling.LANCZOS)
                square_img = Image.new('RGB', size, (255, 255, 255))
                offset = ((size[0] - img.size[0]) // 2, (size[1] - img.size[1]) // 2)
                square_img.paste(img, offset)
                
                img_buffer = BytesIO()
                square_img.save(img_buffer, format='PNG', optimize=True)
                img_buffer.seek(0)
                return img_buffer
                
            except Exception as e:
                logger.warning(f"Failed to process profile image: {e}")
                return None
        else:
            # Get user name for logging
            first_name = getattr(user, "first_name", "")
            last_name = getattr(user, "last_name", "")
            user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
            
            logger.info(f"No profile picture found for user: {user_name} (KEA ID: {user.kea_id})")
            return None
            
    except Exception as e:
        logger.error(f"Error getting profile image: {e}")
        return None

def create_initials_placeholder(user, size=(200, 200)):
    """
    Create a professional placeholder image with user initials in a circular design.
    """
    try:
        # Create square image with transparent background
        img = Image.new('RGBA', size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Define colors
        bg_color = (34, 139, 34, 255)  # KEA Green with full opacity
        border_color = (0, 100, 0, 255)  # Darker green border
        text_color = (255, 255, 255, 255)  # White text
        
        # Draw main circle (slightly smaller to show border)
        margin = 8
        draw.ellipse([margin, margin, size[0]-margin, size[1]-margin], 
                    fill=bg_color, outline=border_color, width=4)
        
        # Get initials from first_name and last_name if available
        first_name = getattr(user, "first_name", "")
        last_name = getattr(user, "last_name", "")
        
        if first_name or last_name:
            if first_name and last_name:
                initials = f"{first_name[0]}{last_name[0]}".upper()
            elif first_name:
                initials = first_name[:2].upper()
            elif last_name:
                initials = last_name[:2].upper()
        else:
            # Fallback to username if no first/last name available
            name = getattr(user, "username", "")
            words = name.strip().split()
            if len(words) >= 2:
                initials = f"{words[0][0]}{words[1][0]}".upper()
            elif len(words) == 1 and len(words[0]) >= 2:
                initials = words[0][:2].upper()
            elif len(words) == 1:
                initials = f"{words[0][0]}A".upper()  # Fallback
            else:
                initials = "KE"  # Default KEA initials
        
        # Try to load a good font, with fallbacks
        font_size = size[0] // 4  # Adjusted for better proportions
        font = None
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/Windows/Fonts/arial.ttf"
        ]
        
        for font_path in font_paths:
            try:
                if os.path.exists(font_path):
                    font = ImageFont.truetype(font_path, font_size)
                    break
            except:
                continue
        
        if not font:
            try:
                # Try default font with size
                font = ImageFont.load_default()
            except:
                font = None
        
        # Calculate text position for centering
        if font:
            bbox = draw.textbbox((0, 0), initials, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        else:
            # Rough estimation without font metrics
            text_width = len(initials) * (font_size * 0.6)
            text_height = font_size
        
        text_x = (size[0] - text_width) // 2
        text_y = (size[1] - text_height) // 2
        
        # Draw the initials
        draw.text((text_x, text_y), initials, fill=text_color, font=font)
        
        # Convert RGBA to RGB with white background for PDF compatibility
        rgb_img = Image.new('RGB', size, (255, 255, 255))
        rgb_img.paste(img, mask=img.split()[-1])  # Use alpha channel as mask
        
        # Convert to buffer
        buffer = BytesIO()
        rgb_img.save(buffer, format='PNG', optimize=True)
        buffer.seek(0)
        
        return buffer
        
    except Exception as e:
        logger.error(f"Error creating initials placeholder: {e}")
        # Very simple fallback - just a gray circle
        try:
            simple_img = Image.new('RGB', size, (255, 255, 255))
            draw = ImageDraw.Draw(simple_img)
            
            # Draw simple gray circle
            margin = 10
            draw.ellipse([margin, margin, size[0]-margin, size[1]-margin], 
                        fill=(180, 180, 180), outline=(120, 120, 120), width=2)
            
            # Add simple text
            draw.text((size[0]//2-10, size[1]//2-10), "USER", fill=(60, 60, 60))
            
            buffer = BytesIO()
            simple_img.save(buffer, format='PNG')
            buffer.seek(0)
            return buffer
        except:
            # Ultimate fallback
            buffer = BytesIO()
            Image.new('RGB', size, (200, 200, 200)).save(buffer, format='PNG')
            buffer.seek(0)
            return buffer


def generate_membership_card_pdf(user, request: HttpRequest):
    """
    Generate a PDF membership card with smaller avatar circle and QR on the right.
    """
    try:
        # Get user name for logging
        first_name = getattr(user, "first_name", "")
        last_name = getattr(user, "last_name", "")
        user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
        
        logger.info(f"Starting PDF generation for user: {user_name} (KEA ID: {user.kea_id})")

        width_mm, height_mm = 54, 86
        width_pt = width_mm * 72 / 25.4
        height_pt = height_mm * 72 / 25.4

        NAVY = (0.129, 0.212, 0.475)
        LABEL = (0.70, 0.80, 0.95)
        WHITE = colors.white
        KEA_GREEN = (34/255, 197/255, 94/255)

        pdf_buffer = BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=(width_pt, height_pt))

        org_line1 = getattr(settings, "ORG_NAME_LINE1", "Kerala Engineers'")
        org_line2 = getattr(settings, "ORG_NAME_LINE2", "Association")
        status_text = "Active" if getattr(user, "is_active", True) else "Inactive"

        def truncate_to_width(text, font_name, font_size, max_w):
            c.setFont(font_name, font_size)
            if c.stringWidth(text, font_name, font_size) <= max_w:
                return text
            ell = "..."
            low, high = 0, len(text)
            while low < high:
                mid = (low + high) // 2
                cand = text[:mid] + ell
                if c.stringWidth(cand, font_name, font_size) <= max_w:
                    low = mid + 1
                else:
                    high = mid
            return text[:max(0, low - 1)] + ell

        # Add a simple wrapper helper
        def wrap_to_width(text, font_name, font_size, max_w):
            words = text.split()
            lines, cur = [], ""
            for w in words:
                test = (cur + " " + w).strip()
                if c.stringWidth(test, font_name, font_size) <= max_w or not cur:
                    cur = test
                else:
                    lines.append(cur)
                    cur = w
            if cur:
                lines.append(cur)
            return lines

        # Background
        c.setFillColorRGB(*NAVY)
        c.rect(0, 0, width_pt, height_pt, fill=1, stroke=0)

        padding = 10

        # Header
        logo_size = 22
        logo_x = padding
        logo_y = height_pt - padding - logo_size
        c.setFillColorRGB(*KEA_GREEN)
        c.circle(logo_x + logo_size / 2, logo_y + logo_size / 2, logo_size / 2, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(logo_x + logo_size / 2, logo_y + logo_size / 2 - 2, "KEA")

        text_x = logo_x + logo_size + 6
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 8)
        c.drawString(text_x, logo_y + logo_size / 2 + 3, org_line1)
        c.setFont("Helvetica", 7)
        c.drawString(text_x, logo_y + logo_size / 2 - 4, org_line2)

        status_right = width_pt - padding
        c.setFillColorRGB(0.85, 0.90, 0.98)
        c.setFont("Helvetica", 6)
        c.drawRightString(status_right, height_pt - padding - 3, "STATUS")
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 8)
        c.drawRightString(status_right, height_pt - padding - 13, status_text)

        # Member name section
        name_block_top = height_pt - 55
        c.setFillColorRGB(*LABEL)
        c.setFont("Helvetica", 6)
        c.drawString(padding, name_block_top, "MEMBER NAME")

        # First name only (capitalized). Fallbacks to username/email local-part.
        first_name = (getattr(user, "first_name", "") or "").strip()
        last_name = (getattr(user, "last_name", "") or "").strip()  # kept if you need initials for avatar
        if first_name:
            member_name = first_name.capitalize()
        else:
            fallback = (getattr(user, "username", "") or "").strip()
            if not fallback:
                fallback = ((getattr(user, "email", "") or "").split("@")[0])
            member_name = (fallback.replace(".", " ").replace("_", " ").split() or ["Member"])[0].capitalize()

        name_font = "Helvetica-Bold"
        name_size = 11
        c.setFillColor(WHITE)
        c.setFont(name_font, name_size)

        # Profile photo (smaller circle)
        photo_size = 40  # reduced from 52
        photo_x = width_pt - photo_size - padding
        photo_y = height_pt - 78  # nudged to keep spacing nice
        ring_extra = 1.8  # thinner ring

        # Name max width ends before the photo
        name_gap_to_photo = 8
        max_name_width = max(40, photo_x - padding - name_gap_to_photo)
        display_name = truncate_to_width(member_name, name_font, name_size, max_name_width)
        c.drawString(padding, name_block_top - 15, display_name)

        # Photo (with white ring) stays here
        c.setFillColor(WHITE)
        c.circle(photo_x + photo_size / 2, photo_y + photo_size / 2, photo_size / 2 + ring_extra, fill=1, stroke=0)

        photo_buffer = get_profile_image_for_pdf(user, request, size=(int(photo_size * 2.83), int(photo_size * 2.83)))
        if photo_buffer:
            try:
                c.saveState()
                p = c.beginPath()
                p.circle(photo_x + photo_size / 2, photo_y + photo_size / 2, photo_size / 2)
                c.clipPath(p, stroke=0, fill=0)
                ReportLabImage(photo_buffer, width=photo_size, height=photo_size).drawOn(c, photo_x, photo_y)
                c.restoreState()
            except Exception as e:
                logger.warning(f"Failed to add profile picture: {e}")
                photo_buffer = None
        if not photo_buffer:
            c.setFillColorRGB(0.30, 0.40, 0.70)
            c.circle(photo_x + photo_size / 2, photo_y + photo_size / 2, photo_size / 2, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 16)
            
            # Get initials from first_name and last_name if available
            if first_name or last_name:
                initials = ""
                if first_name:
                    initials += first_name[0].upper()
                if last_name:
                    initials += last_name[0].upper()
            else:
                initials = "".join([w[0].upper() for w in (member_name or "").split()[:2]]) or "KE"
                
            sw = c.stringWidth(initials, "Helvetica-Bold", 16)
            c.drawString(photo_x + photo_size / 2 - sw / 2, photo_y + photo_size / 2 - 5, initials)

        # Divider 1 (after name section)
        c.setStrokeColor(WHITE)
        c.setLineWidth(0.3)
        c.setDash(1, 2)
        divider1_y = height_pt - 95
        c.line(padding, divider1_y, width_pt - padding, divider1_y)
        c.setDash()  # reset

        # >>> Draw MEMBERSHIP ID and MEMBERSHIP EMAIL between divider1 and divider2 <
        # First label row (ID)
        info_y_id = divider1_y - 14  # place labels inside the band between the two dividers

        # Draw MEMBERSHIP ID label
        c.setFillColorRGB(*LABEL)
        c.setFont("Helvetica", 6)
        c.drawString(padding, info_y_id, "MEMBERSHIP ID")

        # Draw Membership ID value
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 10)
        member_id_raw = str(getattr(user, "kea_id", getattr(user, "id", "")))
        member_id = member_id_raw if member_id_raw.startswith("KEA") else f"KEA{member_id_raw}"
        c.drawString(padding, info_y_id - 14, member_id)

        # Second label row (Email) - positioned below ID
        info_y_email = info_y_id - 26  # Place email section below ID

        # Draw MEMBERSHIP EMAIL label
        c.setFillColorRGB(*LABEL)
        c.setFont("Helvetica", 6)
        c.drawString(padding, info_y_email, "MEMBERSHIP EMAIL")
        
        # Get user's email
        email = getattr(user, "email", "") or ""
        
        # Draw the email with no truncation
        c.setFillColor(WHITE)
        c.setFont("Helvetica", 8)  # Smaller font to fit email
        
        # Draw email
        c.drawString(padding, info_y_email - 14, email)
        
        # Divider 2 (after ID and email section) - MOVED UP TO MATCH IMAGE
        divider2_y = info_y_email - 22  # Position divider after email
        c.setStrokeColor(WHITE)
        c.setLineWidth(0.3)
        c.setDash(1, 2)
        c.line(padding, divider2_y, width_pt - padding, divider2_y)
        c.setDash()
        
        # QR container
        qr_size = 50
        qr_pad = 8
        container_w = qr_size + 2 * qr_pad
        container_h = qr_size + 2 * qr_pad
        container_x = width_pt - container_w - padding
        qr_y = 25
        qr_x = container_x + qr_pad
        container_top = qr_y + qr_size + qr_pad

        # Expiration section - positioned below divider2
        label_y = divider2_y - 14

        # Format date as DD-MM-YYYY
        if hasattr(user, "membership_expiry") and user.membership_expiry:
            try:
                # Format expiry date as DD-MM-YYYY
                expiry_str = user.membership_expiry.strftime("%d-%m-%Y")
            except Exception:
                expiry_str = "24-08-2025"  # Default date if expiry can't be formatted
        else:
            expiry_str = "24-08-2025"  # Default expiry date

        # Draw EXPIRATION label
        c.setFillColorRGB(*LABEL)
        c.setFont("Helvetica", 6)
        c.drawString(padding, label_y, "EXPIRATION")

        # Draw expiration date
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 10)  # Larger font for expiration date
        c.drawString(padding, label_y - 14, expiry_str)

        # Draw QR (right)
        c.setFillColor(WHITE)
        c.roundRect(container_x, qr_y - qr_pad, container_w, container_h, 7, fill=1, stroke=0)
        try:
            qr_buffer = generate_user_qr_code(user)
            ReportLabImage(qr_buffer, width=qr_size, height=qr_size).drawOn(c, qr_x, qr_y)
        except Exception as e:
            logger.warning(f"Failed to add QR code: {e}")
            c.setFillColorRGB(0, 0, 0)
            c.setFont("Helvetica", 8)
            c.drawCentredString(qr_x + qr_size / 2, qr_y + qr_size / 2, "QR CODE")

        # Corner ticks
        c.setStrokeColor(WHITE)
        c.setLineWidth(0.8)
        c.line(5, height_pt - 5, 16, height_pt - 5)
        c.line(5, height_pt - 5, 5, height_pt - 16)
        c.line(width_pt - 5, 5, width_pt - 16, 5)
        c.line(width_pt - 5, 5, width_pt - 5, 16)

        c.showPage()
        c.save()
        pdf_buffer.seek(0)
        logger.info("PDF generation completed successfully")
        return pdf_buffer
    except Exception as e:
        logger.error(f"Error generating membership card PDF: {e}")
        # Fallback simple card
        try:
            error_buffer = BytesIO()
            width_pt = 154
            height_pt = 245
            c = canvas.Canvas(error_buffer, pagesize=(width_pt, height_pt))
            c.setFillColorRGB(*NAVY)
            c.rect(0, 0, width_pt, height_pt, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(10, height_pt - 30, "Membership Card")
            
            # Use first_name and last_name for the fallback card too
            first_name = getattr(user, "first_name", "")
            last_name = getattr(user, "last_name", "")
            if first_name or last_name:
                name = f"{first_name} {last_name}".strip()
            else:
                name = user.username
                
            c.setFont("Helvetica", 10)
            c.drawString(10, height_pt - 50, f"Name: {name}")
            c.drawString(10, height_pt - 70, f"ID: {getattr(user, 'kea_id', getattr(user, 'id', ''))}")
            
            # Add email to fallback card too
            email = getattr(user, "email", "") or ""
            c.drawString(10, height_pt - 90, f"Email: {email}")
            
            # Add expiration date in DD-MM-YYYY format
            if hasattr(user, "membership_expiry") and user.membership_expiry:
                try:
                    expiry_str = user.membership_expiry.strftime("%d-%m-%Y")
                except Exception:
                    expiry_str = "24-08-2025"
            else:
                expiry_str = "24-08-2025"
                
            c.drawString(10, height_pt - 110, f"Expires: {expiry_str}")
            
            c.save()
            error_buffer.seek(0)
            return error_buffer
        except:
            raise

def create_or_update_membership_card(user, request: HttpRequest):
    """
    Updated function that uses the fixed PDF generator
    """
    try:
        # Generate the PDF using the fixed function
        pdf_file = generate_membership_card_pdf(user, request)
        
        # Create directory if it doesn't exist
        membership_cards_dir = os.path.join(settings.MEDIA_ROOT, "membership_cards")
        os.makedirs(membership_cards_dir, exist_ok=True)
        
        # Save the PDF using kea_id instead of user_id
        file_name = f"membership_card_{user.kea_id}.pdf"
        relative_path = os.path.join("membership_cards", file_name)
        full_path = os.path.join(settings.MEDIA_ROOT, relative_path)
        
        with open(full_path, "wb") as f:
            f.write(pdf_file.getvalue())
        
        # Update user's membership_card field if it exists
        if hasattr(user, 'membership_card'):
            user.membership_card.save(file_name, ContentFile(pdf_file.getvalue()), save=True)
        
        # Update URL
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        user.membership_card_url = f"{protocol}://{domain}{settings.MEDIA_URL}{relative_path}"
        user.save(update_fields=['membership_card_url'])
        
        return relative_path
    
    except Exception as e:
        logger.error(f"Error creating/updating membership card: {e}")
        return None

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_membership_card_view(request):
    """
    Generate membership card with all features (QR code, profile picture, etc.)
    """
    try:
        user = request.user
        # Get user name for logging
        first_name = getattr(user, "first_name", "")
        last_name = getattr(user, "last_name", "")
        user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
        
        logger.info(f"Starting membership card generation for user: {user_name} (KEA ID: {user.kea_id})")
        
        # Ensure user has QR code
        if not hasattr(user, 'qr_code') or not user.qr_code:
            logger.info("Creating QR code for user...")
            create_user_with_qr(user)
            user.refresh_from_db()
        
        # Generate PDF
        pdf_buffer = generate_membership_card_pdf(user, request)
        
        if not pdf_buffer:
            return JsonResponse({
                'success': False,
                'message': 'Failed to generate PDF'
            }, status=500)
        
        # Save the PDF using kea_id
        membership_cards_dir = os.path.join(settings.MEDIA_ROOT, "membership_cards")
        os.makedirs(membership_cards_dir, exist_ok=True)
        
        file_name = f"membership_card_{user.kea_id}.pdf"
        relative_path = os.path.join("membership_cards", file_name)
        full_path = os.path.join(settings.MEDIA_ROOT, relative_path)
        
        with open(full_path, "wb") as f:
            f.write(pdf_buffer.getvalue())
        
        # Update user record
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        membership_card_url = f"{protocol}://{domain}{settings.MEDIA_URL}{relative_path}"
        
        user.membership_card_url = membership_card_url
        user.save(update_fields=['membership_card_url'])
        
        logger.info(f"Membership card generated successfully: {membership_card_url}")
        
        return JsonResponse({
            'success': True,
            'message': 'Membership card generated successfully',
            'membership_card_url': membership_card_url,
            'kea_id': user.kea_id
        })
        
    except Exception as e:
        logger.error(f"Error in membership card generation: {e}")
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        }, status=500)

def send_membership_card_email(user, pdf_file):
    """
    Send membership card as email attachment with improved error handling.
    """
    try:
        # Get user name for logging
        first_name = getattr(user, "first_name", "")
        last_name = getattr(user, "last_name", "")
        user_name = f"{first_name} {last_name}".strip() if first_name or last_name else user.username
        
        print(f"🔍 Starting email send process for: {user.email} (KEA ID: {user.kea_id}, Name: {user_name})")
        print(f"🔍 PDF file type: {type(pdf_file)}")
        
        # Convert BytesIO to bytes if necessary
        if isinstance(pdf_file, io.BytesIO):
            # Save current position
            current_pos = pdf_file.tell()
            # Go to beginning and read all content
            pdf_file.seek(0)
            pdf_content = pdf_file.read()
            # Restore position
            pdf_file.seek(current_pos)
            print(f"📄 Converted BytesIO to bytes, size: {len(pdf_content)} bytes")
        elif isinstance(pdf_file, bytes):
            pdf_content = pdf_file
            print(f"📄 Using bytes directly, size: {len(pdf_content)} bytes")
        else:
            print(f"❌ Unsupported PDF file type: {type(pdf_file)}")
            return False
        
        if not pdf_content:
            print("❌ No PDF content available")
            return False
        
        # Email content
        subject = "Your KEA Membership Card"
        
        # Get user's name from first_name and last_name
        if first_name or last_name:
            user_full_name = f"{first_name} {last_name}".strip()
        else:
            user_full_name = user.username
        
        # HTML email body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #22c55e, #16a34a); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 24px;">Kerala Engineers' Association</h1>
                <p style="margin: 10px 0 0 0; font-size: 16px;">Your Membership Card</p>
            </div>
            
            <div style="background-color: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px;">
                <p>Dear <strong>{user_full_name}</strong>,</p>
                
                <p>Congratulations and welcome to the Kerala Engineers' Association (KEA)!</p>
                
                <p>Your membership card (KEA ID: <strong>{user.kea_id}</strong>) is attached to this email as a PDF file. Please download and keep it safe as proof of your membership.</p>
                
                <div style="background-color: #e8f5e8; border-left: 4px solid #22c55e; padding: 15px; margin: 20px 0;">
                    <h3 style="margin: 0 0 10px 0; color: #166534;">What to do next:</h3>
                    <ul style="margin: 0; padding-left: 20px; color: #166534;">
                        <li>Download the attached PDF file</li>
                        <li>Print it on quality paper for best results</li>
                        <li>Keep it with you to enjoy member benefits</li>
                        <li>Present it at KEA events and activities</li>
                    </ul>
                </div>
                
                <p>We look forward to your active participation in our community and events.</p>
                
                <p>If you have any questions or need assistance, please don't hesitate to contact us.</p>
                
                <p style="margin-top: 30px;">
                    <strong>Best Regards,</strong><br>
                    Kerala Engineers' Association (KEA)<br>
                    Bengaluru Chapter
                </p>
            </div>
            
            <div style="text-align: center; padding: 20px; font-size: 12px; color: #666;">
                <p>This is an automated email. Please do not reply to this message.</p>
            </div>
        </body>
        </html>
        """
        
        # Create email message
        email = EmailMessage(
            subject=subject,
            body=html_body,
            from_email=settings.EMAIL_HOST_USER,
            to=[user.email],
        )
        
        # Set content type to HTML
        email.content_subtype = 'html'
        
        # Attach PDF using kea_id in filename
        print(f"📎 Attaching PDF file, size: {len(pdf_content)} bytes")
        email.attach(
            filename=f'KEA_Membership_Card_{user.kea_id}.pdf',
            content=pdf_content,
            mimetype='application/pdf'
        )
        
        # Send the email
        print("📤 Sending email...")
        result = email.send(fail_silently=False)
        print(f"✅ Email send result: {result}")
        
        if result > 0:
            print(f"✅ Email sent successfully to {user.email}")
            logger.info(f"Membership card email sent successfully to {user.email}")
            return True
        else:
            print(f"❌ Email sending failed - result: {result}")
            logger.error(f"Email sending failed for {user.email} - result: {result}")
            return False
        
    except Exception as e:
        print(f"❌ Email sending failed: {str(e)}")
        import traceback
        traceback.print_exc()
        logger.error(f"Failed to send membership card email to {user.email}: {e}")
        return False

