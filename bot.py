import asyncio
import logging
from telegram import Update, ChatMember, ChatPermissions
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json



# Включаем логирование
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# Общий секретный ключ для бота (известен только боту)
BOT_SECRET_KEY = secrets.token_bytes(32)

# Словарь для хранения временных данных пользователей
user_data = {}

# ============= КЛАСС ШИФРОВАНИЯ =============
class UniversalEncryptionHandler:
    @staticmethod
    def _generate_salt():
        """Генерирует случайную соль"""
        return secrets.token_bytes(16)
    
    @staticmethod
    def _derive_key(salt, level=None):
        """Производный ключ на основе соли и уровня шифрования"""
        if level is None:
            level = "default"
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        combined = BOT_SECRET_KEY + level.encode()
        key = base64.urlsafe_b64encode(kdf.derive(combined))
        return key
    
    @staticmethod
    def _xor_cipher(data, key):
        """Простой XOR шифр"""
        key_bytes = key if isinstance(key, bytes) else key.encode()
        result = bytearray()
        key_len = len(key_bytes)
        
        for i in range(len(data)):
            result.append(data[i] ^ key_bytes[i % key_len])
        return bytes(result)
    
    @staticmethod
    def _reverse_and_scramble(text):
        """Реверсирует строку и меняет местами символы"""
        reversed_text = text[::-1]
        bytes_data = reversed_text.encode('utf-8')
        scrambled = bytearray(bytes_data)
        
        for i in range(0, len(scrambled) - 1, 2):
            if i + 1 < len(scrambled):
                scrambled[i], scrambled[i + 1] = scrambled[i + 1], scrambled[i]
        
        if len(scrambled) > 4:
            mid = len(scrambled) // 2
            scrambled = scrambled[mid:] + scrambled[:mid]
        
        return bytes(scrambled)
    
    @staticmethod
    def _unreverse_and_unscramble(data):
        """Восстанавливает оригинальную строку"""
        if len(data) > 4:
            mid = len(data) - (len(data) // 2)
            unscrambled = bytearray(data[mid:] + data[:mid])
        else:
            unscrambled = bytearray(data)
        
        for i in range(0, len(unscrambled) - 1, 2):
            if i + 1 < len(unscrambled):
                unscrambled[i], unscrambled[i + 1] = unscrambled[i + 1], unscrambled[i]
        
        return unscrambled.decode('utf-8')[::-1]
    
    @staticmethod
    def _encode_metadata(level, salt=None):
        """Кодирует метаданные в строку"""
        if salt:
            return base64.urlsafe_b64encode(json.dumps({
                'level': level,
                'salt': salt.hex()
            }).encode()).decode('utf-8')
        else:
            return base64.urlsafe_b64encode(json.dumps({
                'level': level
            }).encode()).decode('utf-8')
    
    @staticmethod
    def _decode_metadata(metadata_str):
        """Декодирует метаданные из строки"""
        decoded = base64.urlsafe_b64decode(metadata_str)
        return json.loads(decoded.decode('utf-8'))

    @staticmethod
    def encrypt_basic(text):
        """Базовый уровень шифрования"""
        salt = UniversalEncryptionHandler._generate_salt()
        xor_key = hashlib.sha256(BOT_SECRET_KEY + salt).hexdigest()[:32]
        xor_encrypted = UniversalEncryptionHandler._xor_cipher(text.encode(), xor_key)
        base64_encoded = base64.b64encode(xor_encrypted).decode('utf-8')
        scrambled = UniversalEncryptionHandler._reverse_and_scramble(base64_encoded)
        metadata = UniversalEncryptionHandler._encode_metadata('basic', salt)
        final_encrypted = base64.urlsafe_b64encode(scrambled).decode('utf-8')
        return f"ENC:{metadata}:{final_encrypted}"
    
    @staticmethod
    def decrypt_basic(encrypted_text):
        """Расшифровка базового уровня"""
        if not encrypted_text.startswith("ENC:"):
            raise ValueError("Неверный формат зашифрованного текста")
        
        parts = encrypted_text[4:].split(':', 1)
        if len(parts) != 2:
            raise ValueError("Неверный формат данных")
        
        metadata_str, final_encrypted = parts
        metadata = UniversalEncryptionHandler._decode_metadata(metadata_str)
        salt = bytes.fromhex(metadata['salt'])
        scrambled = base64.urlsafe_b64decode(final_encrypted)
        base64_encoded = UniversalEncryptionHandler._unreverse_and_unscramble(scrambled)
        xor_encrypted = base64.b64decode(base64_encoded)
        xor_key = hashlib.sha256(BOT_SECRET_KEY + salt).hexdigest()[:32]
        decrypted = UniversalEncryptionHandler._xor_cipher(xor_encrypted, xor_key)
        return decrypted.decode('utf-8')
    
    @staticmethod
    def encrypt_standard(text):
        """Стандартный уровень шифрования"""
        salt = UniversalEncryptionHandler._generate_salt()
        key = UniversalEncryptionHandler._derive_key(salt, 'standard')
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode())
        xor_key = hashlib.sha256(BOT_SECRET_KEY + salt).hexdigest()[:32]
        xor_encrypted = UniversalEncryptionHandler._xor_cipher(encrypted, xor_key)
        metadata = UniversalEncryptionHandler._encode_metadata('standard', salt)
        final_encrypted = base64.urlsafe_b64encode(xor_encrypted).decode('utf-8')
        return f"ENC:{metadata}:{final_encrypted}"
    
    @staticmethod
    def decrypt_standard(encrypted_text):
        """Расшифровка стандартного уровня"""
        if not encrypted_text.startswith("ENC:"):
            raise ValueError("Неверный формат зашифрованного текста")
        
        parts = encrypted_text[4:].split(':', 1)
        if len(parts) != 2:
            raise ValueError("Неверный формат данных")
        
        metadata_str, final_encrypted = parts
        metadata = UniversalEncryptionHandler._decode_metadata(metadata_str)
        salt = bytes.fromhex(metadata['salt'])
        xor_encrypted = base64.urlsafe_b64decode(final_encrypted)
        xor_key = hashlib.sha256(BOT_SECRET_KEY + salt).hexdigest()[:32]
        encrypted = UniversalEncryptionHandler._xor_cipher(xor_encrypted, xor_key)
        key = UniversalEncryptionHandler._derive_key(salt, 'standard')
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        return decrypted.decode('utf-8')
    
    @staticmethod
    def encrypt_maximum(text):
        """Максимальный уровень шифрования"""
        salt = UniversalEncryptionHandler._generate_salt()
        scrambled1 = UniversalEncryptionHandler._reverse_and_scramble(text)
        key1 = UniversalEncryptionHandler._derive_key(salt, 'maximum_1')
        fernet1 = Fernet(key1)
        encrypted1 = fernet1.encrypt(scrambled1)
        base64_encoded = base64.b64encode(encrypted1).decode('utf-8')
        scrambled2 = UniversalEncryptionHandler._reverse_and_scramble(base64_encoded)
        xor_key = hashlib.sha256(BOT_SECRET_KEY + salt + b'maximum').hexdigest()[:32]
        xor_encrypted = UniversalEncryptionHandler._xor_cipher(scrambled2, xor_key)
        key2 = UniversalEncryptionHandler._derive_key(salt, 'maximum_2')
        fernet2 = Fernet(key2)
        encrypted2 = fernet2.encrypt(xor_encrypted)
        metadata = UniversalEncryptionHandler._encode_metadata('maximum', salt)
        final_encrypted = base64.urlsafe_b64encode(encrypted2).decode('utf-8')
        return f"ENC:{metadata}:{final_encrypted}"
    
    @staticmethod
    def decrypt_maximum(encrypted_text):
        """Расшифровка максимального уровня"""
        if not encrypted_text.startswith("ENC:"):
            raise ValueError("Неверный формат зашифрованного текста")
        
        parts = encrypted_text[4:].split(':', 1)
        if len(parts) != 2:
            raise ValueError("Неверный формат данных")
        
        metadata_str, final_encrypted = parts
        metadata = UniversalEncryptionHandler._decode_metadata(metadata_str)
        salt = bytes.fromhex(metadata['salt'])
        encrypted2 = base64.urlsafe_b64decode(final_encrypted)
        key2 = UniversalEncryptionHandler._derive_key(salt, 'maximum_2')
        fernet2 = Fernet(key2)
        xor_encrypted = fernet2.decrypt(encrypted2)
        xor_key = hashlib.sha256(BOT_SECRET_KEY + salt + b'maximum').hexdigest()[:32]
        scrambled2 = UniversalEncryptionHandler._xor_cipher(xor_encrypted, xor_key)
        base64_encoded = UniversalEncryptionHandler._unreverse_and_unscramble(scrambled2)
        encrypted1 = base64.b64decode(base64_encoded)
        key1 = UniversalEncryptionHandler._derive_key(salt, 'maximum_1')
        fernet1 = Fernet(key1)
        scrambled1 = fernet1.decrypt(encrypted1)
        decrypted = UniversalEncryptionHandler._unreverse_and_unscramble(scrambled1)
        return decrypted
    
    @staticmethod
    def auto_decrypt(encrypted_text):
        """Автоматически определяет уровень и расшифровывает"""
        if not encrypted_text.startswith("ENC:"):
            raise ValueError("Неверный формат зашифрованного текста")
        
        parts = encrypted_text[4:].split(':', 1)
        if len(parts) != 2:
            raise ValueError("Неверный формат данных")
        
        metadata_str = parts[0]
        metadata = UniversalEncryptionHandler._decode_metadata(metadata_str)
        level = metadata['level']
        
        if level == 'basic':
            return UniversalEncryptionHandler.decrypt_basic(encrypted_text)
        elif level == 'standard':
            return UniversalEncryptionHandler.decrypt_standard(encrypted_text)
        elif level == 'maximum':
            return UniversalEncryptionHandler.decrypt_maximum(encrypted_text)
        else:
            raise ValueError(f"Неизвестный уровень шифрования: {level}")

# ============= ФУНКЦИИ АДМИНИСТРИРОВАНИЯ =============

# Проверка, является ли пользователь Владельцем (тобой)
def is_owner(update: Update) -> bool:
    user_id = update.effective_user.id
    if user_id != YOUR_USER_ID:
        return False
    return True

# Проверка, есть ли у бота права в чате
async def bot_is_admin(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> bool:
    bot_member = await context.bot.get_chat_member(chat_id, context.bot.id)
    return bot_member.status in [ChatMember.ADMINISTRATOR, ChatMember.OWNER]

# ---- КОМАНДЫ АДМИНИСТРИРОВАНИЯ (ТОЛЬКО ДЛЯ ТЕБЯ) ----

# Команда /ban (Бан участника)
async def ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        await update.message.reply_text(" ")
        return

    chat = update.effective_chat
    if not await bot_is_admin(context, chat.id):
        await update.message.reply_text("❌ У бота нет прав администратора в этом чате.")
        return

    if not context.args and not update.message.reply_to_message:
        await update.message.reply_text("Использование: /ban @username или /ban [reply на сообщение]")
        return

    try:
        user_to_ban = None
        if update.message.reply_to_message:
            user_to_ban = update.message.reply_to_message.from_user
        else:
            username = context.args[0].lstrip('@')
            user_to_ban = await context.bot.get_chat_member(chat.id, username)

        if user_to_ban:
            await context.bot.ban_chat_member(chat.id, user_to_ban.user.id)
            await update.message.reply_text(f"Пользователь {user_to_ban.user.full_name} забанен.")
        else:
            await update.message.reply_text("Пользователь не найден.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

# Команда /unban (Разбан)
async def unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    if not context.args:
        await update.message.reply_text("Использование: /unban @username")
        return

    try:
        username = context.args[0].lstrip('@')
        chat = update.effective_chat
        member = await context.bot.get_chat_member(chat.id, username)
        await context.bot.unban_chat_member(chat.id, member.user.id, only_if_banned=True)
        await update.message.reply_text(f"Пользователь {member.user.full_name} разбанен.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

# Команда /kick (Кикнуть участника)
async def kick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    user_to_kick = None
    if update.message.reply_to_message:
        user_to_kick = update.message.reply_to_message.from_user
    elif context.args:
        try:
            username = context.args[0].lstrip('@')
            user_to_kick = await context.bot.get_chat_member(update.effective_chat.id, username)
        except:
            pass

    if user_to_kick:
        try:
            await context.bot.ban_chat_member(update.effective_chat.id, user_to_kick.id)
            await context.bot.unban_chat_member(update.effective_chat.id, user_to_kick.id)
            await update.message.reply_text(f"Пользователь {user_to_kick.full_name} кикнут.")
        except Exception as e:
            await update.message.reply_text(f"Ошибка: {e}")
    else:
        await update.message.reply_text("Укажите пользователя (реплай или @username).")

# Команда /mute (Мут)
async def mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    if not context.args:
        await update.message.reply_text("Использование: /mute [время в минутах] @username. Пример: /mute 10 @durov")
        return

    try:
        time_minutes = int(context.args[0])
        username = context.args[1].lstrip('@')
        chat = update.effective_chat
        member = await context.bot.get_chat_member(chat.id, username)

        permissions = ChatPermissions(can_send_messages=False)
        until_date = None
        if time_minutes > 0:
            from datetime import datetime, timedelta
            until_date = datetime.now() + timedelta(minutes=time_minutes)

        await context.bot.restrict_chat_member(chat.id, member.user.id, permissions, until_date=until_date)
        await update.message.reply_text(f"Пользователь {member.user.full_name} замучен на {time_minutes} мин.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

# Команда /unmute (Размут)
async def unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    user_to_unmute = None
    if update.message.reply_to_message:
        user_to_unmute = update.message.reply_to_message.from_user
    elif context.args:
        try:
            username = context.args[0].lstrip('@')
            user_to_unmute = await context.bot.get_chat_member(update.effective_chat.id, username)
        except:
            pass

    if user_to_unmute:
        try:
            permissions = ChatPermissions(
                can_send_messages=True,
                can_send_media_messages=True,
                can_send_polls=True,
                can_send_other_messages=True,
                can_add_web_page_previews=True
            )
            await context.bot.restrict_chat_member(update.effective_chat.id, user_to_unmute.id, permissions)
            await update.message.reply_text(f"Пользователь {user_to_unmute.full_name} размучен.")
        except Exception as e:
            await update.message.reply_text(f"Ошибка: {e}")
    else:
        await update.message.reply_text("Укажите пользователя.")

# Команда /setdesc (Изменить описание)
async def set_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    new_description = " ".join(context.args)
    if not new_description:
        await update.message.reply_text("Использование: /setdesc Новое описание канала")
        return

    try:
        await context.bot.set_chat_description(update.effective_chat.id, new_description)
        await update.message.reply_text("✅ Описание чата обновлено.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

# Команда /settitle (Изменить название)
async def set_title(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    new_title = " ".join(context.args)
    if not new_title:
        await update.message.reply_text("Использование: /settitle Новое название чата")
        return

    try:
        await context.bot.set_chat_title(update.effective_chat.id, new_title)
        await update.message.reply_text("✅ Название чата обновлено.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

# Команда /promote (Назначить админом)
async def promote(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    user_to_promote = None
    if update.message.reply_to_message:
        user_to_promote = update.message.reply_to_message.from_user
    elif context.args:
        try:
            username = context.args[0].lstrip('@')
            user_to_promote = await context.bot.get_chat_member(update.effective_chat.id, username)
        except:
            pass

    if user_to_promote:
        try:
            await context.bot.promote_chat_member(
                chat_id=update.effective_chat.id,
                user_id=user_to_promote.id,
                can_change_info=True,
                can_invite_users=True,
                can_delete_messages=True,
                can_edit_messages=True,
                can_post_messages=True,
                can_pin_messages=True,
                can_promote_members=False,
                can_restrict_members=True,
                can_manage_video_chats=True,
                can_manage_chat=True,
                can_manage_topics=True
            )
            await update.message.reply_text(f"✅ Пользователь {user_to_promote.full_name} назначен админом (без права назначать других).")
        except Exception as e:
            await update.message.reply_text(f"Ошибка: {e}")
    else:
        await update.message.reply_text("Укажите пользователя.")

# Команда /demote (Снять с админки)
async def demote(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    user_to_demote = None
    if update.message.reply_to_message:
        user_to_demote = update.message.reply_to_message.from_user
    elif context.args:
        try:
            username = context.args[0].lstrip('@')
            user_to_demote = await context.bot.get_chat_member(update.effective_chat.id, username)
            user_to_demote = user_to_demote.user
        except Exception as e:
            await update.message.reply_text(f"Ошибка: {e}")
            return

    if user_to_demote:
        try:
            # Убираем все права администратора
            await context.bot.promote_chat_member(
                chat_id=update.effective_chat.id,
                user_id=user_to_demote.id,
                can_change_info=False,
                can_invite_users=False,
                can_delete_messages=False,
                can_edit_messages=False,
                can_post_messages=False,
                can_pin_messages=False,
                can_promote_members=False,
                can_restrict_members=False,
                can_manage_video_chats=False,
                can_manage_chat=False,
                can_manage_topics=False
            )
            await update.message.reply_text(f"✅ Пользователь {user_to_demote.full_name} снят с админки.")
        except Exception as e:
            await update.message.reply_text(f"Ошибка: {e}")
    else:
        await update.message.reply_text("Укажите пользователя (реплай или @username).")

# Команда /del (Удалить сообщение)
async def delete_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    if update.message.reply_to_message:
        try:
            await context.bot.delete_message(update.effective_chat.id, update.message.reply_to_message.message_id)
            await update.message.delete()  # Удаляем команду /del
        except Exception as e:
            await update.message.reply_text(f"Не могу удалить: {e}")
    else:
        await update.message.reply_text("Ответьте на сообщение, которое нужно удалить.")

# Команда /pin (Закрепить сообщение)
async def pin_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    if update.message.reply_to_message:
        try:
            await context.bot.pin_chat_message(update.effective_chat.id, update.message.reply_to_message.message_id)
            await update.message.reply_text("✅ Сообщение закреплено.")
        except Exception as e:
            await update.message.reply_text(f"Ошибка: {e}")
    else:
        await update.message.reply_text("Ответьте на сообщение, которое нужно закрепить.")

# Команда /unpin (Открепить)
async def unpin_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return
    if not await bot_is_admin(context, update.effective_chat.id):
        await update.message.reply_text("Hello")
        return

    try:
        await context.bot.unpin_chat_message(update.effective_chat.id)
        await update.message.reply_text("✅ Сообщение откреплено.")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

# Команда /whois (Узнать инфо о пользователе)
async def whois(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return

    user_info = None
    if update.message.reply_to_message:
        user_info = update.message.reply_to_message.from_user
    elif context.args:
        try:
            username = context.args[0].lstrip('@')
            user_info = await context.bot.get_chat_member(update.effective_chat.id, username)
            user_info = user_info.user
        except Exception as e:
            await update.message.reply_text(f"Не найден: {e}")
            return
    else:
        user_info = update.effective_user

    if user_info:
        text = f"🆔 ID: `{user_info.id}`\n"
        text += f"👤 Имя: {user_info.full_name}\n"
        text += f"📛 Юзернейм: @{user_info.username}" if user_info.username else "📛 Юзернейм: нет"
        await update.message.reply_text(text, parse_mode="Markdown")
    else:
        await update.message.reply_text("Не удалось получить информацию.")

# ============= КОМАНДЫ ШИФРОВАНИЯ (ДЛЯ ВСЕХ) =============

async def encrypt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Начало процесса шифрования"""
    user_id = update.effective_user.id
    user_data[user_id] = {'mode': 'waiting_for_encryption_level'}
    
    from telegram import ReplyKeyboardMarkup
    markup = ReplyKeyboardMarkup([['🔸 Базовый', '🔹 Стандартный', '🔺 Максимум'], ['❌ Отмена']], 
                                 one_time_keyboard=True, resize_keyboard=True)
    
    await update.message.reply_text(
        "🔒 *Выберите уровень шифрования:*\n\n"
        "🔸 *Базовый* - быстрое шифрование\n"
        "🔹 *Стандартный* - надежная защита\n"
        "🔺 *Максимум* - максимальная безопасность\n\n"
        "*Примечание:* Любой пользователь сможет расшифровать это сообщение через этого бота.",
        reply_markup=markup,
        parse_mode='Markdown')

async def decrypt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Начало процесса расшифровки"""
    user_id = update.effective_user.id
    user_data[user_id] = {'mode': 'waiting_for_decryption'}
    
    from telegram import ReplyKeyboardRemove
    await update.message.reply_text(
        "🔓 *Расшифровка сообщения*\n\n"
        "Вставьте зашифрованный текст для расшифровки.\n"
        "Это может быть ваше или чужое сообщение!\n\n"
        "*Формат:* ENC:xxxxxxxx:xxxxxxxx\n\n"
        "Бот автоматически определит уровень шифрования.",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode='Markdown')

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Информация о шифровании"""
    info_text = """
🔍 *Информация о шифровании*

*Как это работает:*
1. При шифровании генерируется уникальная "соль"
2. Соль сохраняется в зашифрованном сообщении
3. Бот использует свой секретный ключ + соль для шифрования/дешифрования
4. Любой пользователь может расшифровать любое сообщение

*Безопасность:*
• Секретный ключ известен только боту
• Каждое сообщение имеет уникальную соль
• Многослойные алгоритмы шифрования
• Невозможно расшифровать без этого бота

*Пример зашифрованного сообщения:*
`ENC:eyJsZXZlbCI6...:G9tZXN0aWNfY...`

*Для пересылки:*
1. Зашифруйте сообщение
2. Скопируйте результат (начинается с ENC:)
3. Отправьте другу
4. Друг использует /decrypt в этом боте
"""
    await update.message.reply_text(info_text, parse_mode='Markdown')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /start"""
    welcome_text = """
🔐 *Универсальный бот с функциями администратора и шифрования*

*Команды администратора (только для владельца):*
/ban - Забанить пользователя
/unban - Разбанить пользователя
/kick - Кикнуть пользователя
/mute - Замутить пользователя
/unmute - Размутить пользователя
/setdesc - Изменить описание чата
/settitle - Изменить название чата
/promote - Назначить администратором
/demote - Снять с админки
/del - Удалить сообщение
/pin - Закрепить сообщение
/unpin - Открепить сообщение
/whois - Информация о пользователе

*Команды шифрования (для всех):*
/encrypt - Зашифровать текст
/decrypt - Расшифровать текст
/info - Информация о шифровании

*Как использовать шифрование:*
1. Зашифровать: /encrypt → выбрать уровень → ввести текст
2. Расшифровать: /decrypt → вставить зашифрованный текст
3. Отправить другу: скопировать результат и отправить

*Особенности:*
• Любой пользователь может расшифровать любое сообщение
• Уровень шифрования определяется автоматически
• Команды администрирования доступны только владельцу
"""
    await update.message.reply_text(welcome_text, parse_mode='Markdown')

# ============= ОБРАБОТЧИК ТЕКСТОВЫХ СООБЩЕНИЙ =============

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик всех текстовых сообщений"""
    user_id = update.effective_user.id
    message_text = update.message.text
    
    # Обработка отмены
    if message_text == '❌ Отмена':
        if user_id in user_data:
            del user_data[user_id]
        from telegram import ReplyKeyboardRemove
        await update.message.reply_text("Операция отменена.", reply_markup=ReplyKeyboardRemove())
        return
    
    # Режим ожидания уровня шифрования
    if user_id in user_data and user_data[user_id].get('mode') == 'waiting_for_encryption_level':
        level_map = {
            '🔸 Базовый': 'basic',
            '🔹 Стандартный': 'standard',
            '🔺 Максимум': 'maximum'
        }
        
        if message_text in level_map:
            user_data[user_id]['level'] = level_map[message_text]
            user_data[user_id]['mode'] = 'waiting_for_text'
            
            level_names = {
                'basic': '🔸 Базовый',
                'standard': '🔹 Стандартный',
                'maximum': '🔺 Максимум'
            }
            
            from telegram import ReplyKeyboardRemove
            await update.message.reply_text(
                f"✅ Выбран уровень: {level_names[level_map[message_text]]}\n\n"
                f"Теперь введите текст для шифрования:",
                reply_markup=ReplyKeyboardRemove())
        else:
            await update.message.reply_text("Пожалуйста, выберите уровень шифрования из предложенных вариантов.")
        return
    
    # Режим ожидания текста для шифрования
    if user_id in user_data and user_data[user_id].get('mode') == 'waiting_for_text':
        text = message_text
        level = user_data[user_id]['level']
        
        try:
            if level == 'basic':
                encrypted = UniversalEncryptionHandler.encrypt_basic(text)
                level_name = "🔸 Базовый"
                description = "Быстрое шифрование"
            elif level == 'standard':
                encrypted = UniversalEncryptionHandler.encrypt_standard(text)
                level_name = "🔹 Стандартный"
                description = "Надежная защита"
            elif level == 'maximum':
                encrypted = UniversalEncryptionHandler.encrypt_maximum(text)
                level_name = "🔺 Максимум"
                description = "Максимальная безопасность"
            
            from telegram import ReplyKeyboardRemove
            await update.message.reply_text(
                f"✅ *Текст успешно зашифрован!*\n\n"
                f"*Уровень:* {level_name}\n"
                f"*Описание:* {description}\n\n"
                f"*Зашифрованный текст:*\n"
                f"```\n{encrypted}\n```\n\n"
                f"*Для расшифровки:*\n"
                f"• Любой пользователь может использовать /decrypt\n"
                f"• Просто скопируйте текст выше\n\n"
                f"*Длина:* {len(encrypted)} символов",
                parse_mode='Markdown',
                reply_markup=ReplyKeyboardRemove())
            
            del user_data[user_id]
            
        except Exception as e:
            logger.error(f"Ошибка при шифровании: {e}")
            await update.message.reply_text("❌ Произошла ошибка при шифровании. Попробуйте еще раз.")
            del user_data[user_id]
        return
    
    # Режим ожидания текста для расшифровки
    if user_id in user_data and user_data[user_id].get('mode') == 'waiting_for_decryption':
        encrypted_text = message_text
        
        try:
            if not encrypted_text.startswith('ENC:'):
                await update.message.reply_text(
                    "❌ *Неверный формат!*\n\n"
                    "Зашифрованный текст должен начинаться с 'ENC:'\n"
                    "Пример: 'ENC:eyJsZXZlbCI6...:G9tZXN0aWNfY...'\n\n"
                    "Скопируйте зашифрованное сообщение полностью.",
                    parse_mode='Markdown')
                del user_data[user_id]
                return
            
            decrypted = UniversalEncryptionHandler.auto_decrypt(encrypted_text)
            
            parts = encrypted_text[4:].split(':', 1)
            if len(parts) != 2:
                await update.message.reply_text("❌ *Неверный формат данных!*", parse_mode='Markdown')
                del user_data[user_id]
                return
                
            metadata_str = parts[0]
            metadata = UniversalEncryptionHandler._decode_metadata(metadata_str)
            level = metadata['level']
            
            level_names = {
                'basic': '🔸 Базовый',
                'standard': '🔹 Стандартный',
                'maximum': '🔺 Максимум'
            }
            
            from telegram import ReplyKeyboardRemove
            await update.message.reply_text(
                f"✅ *Текст успешно расшифрован!*\n\n"
                f"*Уровень шифрования:* {level_names.get(level, 'Неизвестный')}\n"
                f"*Исходный текст:*\n"
                f"```\n{decrypted}\n```\n\n"
                f"*Совет:* Вы тоже можете зашифровать текст командой /encrypt",
                parse_mode='Markdown',
                reply_markup=ReplyKeyboardRemove())
            
            del user_data[user_id]
            
        except Exception as e:
            logger.error(f"Ошибка при расшифровке: {e}")
            await update.message.reply_text(
                "❌ *Не удалось расшифровать текст!*\n\n"
                "Возможные причины:\n"
                "• Текст поврежден или неполный\n"
                "• Использована другая система шифрования\n"
                "• Неверный формат данных\n\n"
                "Убедитесь, что:\n"
                "1. Вы скопировали текст полностью\n"
                "2. Текст начинается с 'ENC:'\n"
                "3. Это сообщение было зашифровано этим ботом",
                parse_mode='Markdown')
            del user_data[user_id]
        return

# ============= ОСНОВНАЯ ФУНКЦИЯ =============

def main():
    """Основная функция для запуска бота"""
    app = Application.builder().token(TOKEN).build()

    # Регистрируем команды администрирования
    app.add_handler(CommandHandler("ban", ban))
    app.add_handler(CommandHandler("unban", unban))
    app.add_handler(CommandHandler("kick", kick))
    app.add_handler(CommandHandler("mute", mute))
    app.add_handler(CommandHandler("unmute", unmute))
    app.add_handler(CommandHandler("setdesc", set_description))
    app.add_handler(CommandHandler("settitle", set_title))
    app.add_handler(CommandHandler("promote", promote))
    app.add_handler(CommandHandler("demote", demote))
    app.add_handler(CommandHandler("del", delete_message))
    app.add_handler(CommandHandler("pin", pin_message))
    app.add_handler(CommandHandler("unpin", unpin_message))
    app.add_handler(CommandHandler("whois", whois))
    
    # Регистрируем команды шифрования
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("encrypt", encrypt))
    app.add_handler(CommandHandler("decrypt", decrypt))
    app.add_handler(CommandHandler("info", info))
    
    # Регистрируем обработчик текстовых сообщений
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Запуск бота
    logger.info("Бот запущен...")
    logger.info(f"Секретный ключ бота сгенерирован: {len(BOT_SECRET_KEY)} байт")
    app.run_polling()

if __name__ == "__main__":
    main()