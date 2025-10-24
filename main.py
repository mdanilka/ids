import time
import pyshark
import json
import configparser
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (CallbackQuery, InlineKeyboardButton,
                           InlineKeyboardMarkup, Message)
import asyncio
from aiogram.types import FSInputFile
API_URL = 'https://api.telegram.org/bot'
capture = pyshark.LiveCapture("wlp1s0") 
capture.sniff(timeout=60)
cnt={}
tm={}
reply_id={}
chat_id=1077211564
BOT_TOKEN='6072039986:AAFzr1rgKSZQ8ZlzettJtqmqNJ6NTdXICAA'
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def doc(chat_id,document,caption,reply_markup):
    return await bot.send_document(chat_id=chat_id,document=document,caption=caption,reply_markup=reply_markup)
def wq(packet,data,ip_address):
    button_1 = InlineKeyboardButton(
        text='add IP to whitelist',
        callback_data=ip_address
    )
    keyboard = InlineKeyboardMarkup(inline_keyboard=[[button_1]])
    w=open("packet.txt","w")
    w.write(str(packet))
    w.close()
    #document={'document': open("packet.txt", 'rb')}
    #try:
    r=asyncio.get_event_loop().run_until_complete(doc(chat_id,FSInputFile('packet.txt'),data['caption'],keyboard))
    reply_id[str(ip_address)]=r.message_id
    #await asyncio.sleep(10)
    #except:
        #return ;
weerrt=0;
cooldown=0
amount=0
length=0
for packet in capture.sniff_continuously():
    
    config = configparser.ConfigParser()
    config.read("config.txt")
    if(weerrt%10000==0):
        cooldown=float(config['parameters']['cooldown'])
        amount=int(config['parameters']['amount'])
        length=int(config['parameters']['length'])
    weerrt+=1
    data={'caption':f"Suspucious packet detected\n"}
    ip_address="";
    #print("Length:",len(packet))
    data["caption"]+=f"Length:{len(packet)}\n"
    try:
        ip=packet["ip"] 
        #print("Source Address:",ip.src)
        ip_address=ip.src;
        #print("Destination Address:",ip.dst)
        #print("IP Protocol:",ip.proto)
        data["caption"]+=f"Source Address:{ip.src}\n"
        data["caption"]+=f"Destination Address:{ip.dst}\n"
        data["caption"]+=f"IP Protocol:{ip.proto}\n"
    except:
        try:
            ipv6=packet["ipv6"] 
            #print("Source Address:",ipv6.src)
            ip_address=ipv6.src;
            #print("Destination Address:",ipv6.dst)
            #print("IP Protocol:",ip.proto)
            data["caption"]+=f"Source Address:{ipv6.src}\n"
            data["caption"]+=f"Destination Address:{ipv6.dst}\n"
            data["caption"]+=f"IP Protocol:{ip.proto}\n"
        except:
            try:
                eth=packet['eth']
                ip_address=eth.addr;
                data["caption"]+=f"MAC address:{ip_address}\n"
            except:
                #print("No IP address detected")
                data["caption"]+=f"No IP address detected\n"
    try:
        config = configparser.ConfigParser()
        config.read("whitelist.txt")
        if(config['ip'][str(ip_address).replace(":","A")]=='True'):
            continue
    except:
        try:
            proto=0
            if('tcp' in packet):
                proto=packet['tcp']
            else:
                proto=packet['udp']
            #print("Source Port:",proto.srcport)
            #print("Destination Port:",proto.dstport)
            data["caption"]+=f"Source Port:{proto.srcport}\n"
            data["caption"]+=f"Destination Port:{proto.srcport}\n"
        except:
            #print("No Source and destination ports detected")
            data["caption"]+=f"No Source and destination ports detected\n"
        try:
            cnt[ip_address]+=1;
        except:
            cnt[ip_address]=1;
        try:
            tm[ip_address]=tm[ip_address]
        except:
            tm[ip_address]=time.time()
        if(cnt[ip_address]>=amount and time.time()-tm[ip_address]<cooldown):
            try:
                if(cnt[ip_address]%100==0):
                    button_1 = InlineKeyboardButton(
                        text='add IP to whitelist',
                        callback_data=ip_address
                    )
                    keyboard = InlineKeyboardMarkup(inline_keyboard=[[button_1]])
                    w=open("packet.txt","w")
                    w.write(str(packet))
                    w.close()
                    #document={'document': open("packet.txt", 'rb')}
                    #try:
                    asyncio.get_event_loop().run_until_complete(bot.edit_message_caption(caption=data['caption']+f"Количество изменений={cnt[ip_address]}",chat_id=chat_id,message_id=reply_id[ip_address],reply_markup=keyboard))

            except:
                wq(packet,data,ip_address)
        tm[ip_address]=time.time();
button_1 = InlineKeyboardButton(
    text='edit cooldown',
    callback_data='edit_cooldown_pressed'
)

button_2 = InlineKeyboardButton(
    text='edit amount',
    callback_data='edit_amount_pressed'
)

button_3 = InlineKeyboardButton(
    text='edit length',
    callback_data='edit_length_pressed'
)

button_4 = InlineKeyboardButton(
    text='edit restart time',
    callback_data='edit_tim_pressed'
)
keyboard = InlineKeyboardMarkup(
    inline_keyboard=[[button_1],
                     [button_2],
                     [button_3],
                     [button_4]])
try_button1= InlineKeyboardButton(
    text='try again',
    callback_data='edit_cooldown_pressed'
)
try_button2= InlineKeyboardButton(
    text='try again',
    callback_data='edit_amount_pressed'
)
try_button3= InlineKeyboardButton(
    text='try again',
    callback_data='edit_length_pressed'
)
try_button4= InlineKeyboardButton(
    text='try again',
    callback_data='edit_tim_pressed'
)
try_keyboard1 = InlineKeyboardMarkup(
    inline_keyboard=[[try_button1]])
try_keyboard2 = InlineKeyboardMarkup(
    inline_keyboard=[[try_button2]])
try_keyboard3 = InlineKeyboardMarkup(
    inline_keyboard=[[try_button3]])
try_keyboard4 = InlineKeyboardMarkup(
    inline_keyboard=[[try_button4]])
@dp.message(Command("add"))
async def process_start_command(message: Message):
    global current
    await message.answer(
        "which ip do you prefer to add to whitelist?",
    )
    current="add"

@dp.message(Command("delete"))
async def process_start_command(message: Message):
    global current
    await message.answer(
        "which ip do you prefer to delete from whitelist?",
    )
    current="delete"

@dp.message(Command("settings"))
async def process_start_command(message: Message):
    await message.answer(
        "which parameter do you prefer to change?",
        reply_markup=keyboard
    )
@dp.callback_query(F.data == 'edit_cooldown_pressed')
async def process_button_1_press(callback: CallbackQuery):
    global current
    if callback.message.text != 'edit_cooldown_pressed':
        current="cooldown"
        await callback.message.answer(text='Write right here new value of cooldown parameter')


@dp.callback_query(F.data == 'edit_amount_pressed')
async def process_button_2_press(callback: CallbackQuery):
    global current
    if callback.message.text != 'edit_amount_pressed':
        current="amount"
        await callback.message.answer(text='Write right here new value of amount parameter')

@dp.callback_query(F.data == 'edit_length_pressed')
async def process_button_3_press(callback: CallbackQuery):
    global current
    if callback.message.text != 'edit_length_pressed':
        current="length"
        await callback.message.answer(text='Write right here new value of length parameter')

@dp.callback_query(F.data == 'edit_tim_pressed')
async def process_button_3_press(callback: CallbackQuery):
    global current
    if callback.message.text != 'edit_tim_pressed':
        current="tim"
        await callback.message.answer(text='Write right here new value of restart time parameter')

@dp.callback_query()
async def add_ip_to_whitelist(callback: CallbackQuery):
    print(callback)
    w=open("whitelist.txt","a")
    w.write(f'\n{callback.data.replace(":","A")}=True')
    w.close()
    await callback.message.answer(text=f'{callback.data} added to whitelist')

@dp.message()
async def any(message):
    global current
    print(current)
    if(current=="cooldown"):
        try:
            qqq=float(message.text)
            config = configparser.ConfigParser()
            config.read("config.txt")
            w=open("config.txt","w")
            w.write(str(f'[parameters]\ncooldown={qqq}\namount={config["parameters"]["amount"]}\nlength={config["parameters"]["length"]}\ntim={config["parameters"]["tim"]}'))
            w.close()
            await message.answer("Your edit is successfull")
        except:
            await message.answer("Error. Your edit is unsuccessfull",
                                 reply_markup=try_keyboard1)
        current=""
    if(current=="amount"):
        try:
            qqq=int(message.text)
            config = configparser.ConfigParser()
            config.read("config.txt")
            w=open("config.txt","w")
            w.write(str(f'[parameters]\ncooldown={config["parameters"]["cooldown"]}\namount={qqq}\nlength={config["parameters"]["length"]}\ntim={config["parameters"]["tim"]}'))
            w.close()
            await message.answer("Your edit is successfull")
        except:
            await message.answer("Error. Your edit is unsuccessfull",
                                 reply_markup=try_keyboard2)
        current=""
    if(current=="length"):
        try:
            qqq=int(message.text)
            config = configparser.ConfigParser()
            config.read("config.txt")
            w=open("config.txt","w")
            w.write(str(f'[parameters]\ncooldown={config["parameters"]["cooldown"]}\namount={config["parameters"]["amount"]}\nlength={qqq}\ntim={config["parameters"]["tim"]}'))
            w.close()
            await message.answer("Your edit is successfull")
        except:
            await message.answer("Error. Your edit is unsuccessfull",
                                 reply_markup=try_keyboard3)
        current=""
    if(current=="tim"):
        try:
            qqq=int(message.text)
            config = configparser.ConfigParser()
            config.read("config.txt")
            w=open("config.txt","w")
            w.write(str(f'[parameters]\ncooldown={config["parameters"]["cooldown"]}\namount={config["parameters"]["amount"]}\nlength={config["parameters"]["length"]}\ntim={qqq}'))
            w.close()
            await message.answer("Your edit is successfull")
        except:
            await message.answer("Error. Your edit is unsuccessfull",
                                 reply_markup=try_keyboard4)
        current=""
    if(current=="add"):
        try:
            config = configparser.ConfigParser()
            config.read("whitelist.txt")
            j=config['ip'][message.text]
            await message.answer("this ip is already in whitelist")
        except:
            r=open("whitelist.txt","a")
            r.write(f'\n{message.text.replace(":","A")}=True')
            r.close()
            await message.answer(f'successfull added {message.text} to whitelist')
    if(current=="delete"):
        if(True):
            text=message.text.replace(":","A")
            config = configparser.ConfigParser()
            config.read("whitelist.txt")
            j=config['ip'][text]
            w=open("example_whitelist.txt","w")
            r=open("whitelist.txt","r")
            while True:
                line = r.readline()
                if not line:
                    break
                if(line.strip()!=str(text)+"=True"):
                    if(line.strip()=="[ip]"):
                        w.write(line.strip())
                    else:
                        w.write("\n"+line.strip())
            w.close()
            r.close()
            w=open("whitelist.txt","w")
            r=open("example_whitelist.txt","r")
            while True:
                line = r.readline()
                if not line:
                    break
                if(line.strip()!=str(text)+"=True"):
                    if(line.strip()=="[ip]"):
                        w.write(line.strip())
                    else:
                        w.write("\n"+line.strip())
            w.close()
            r.close()
            await message.answer(f"successfull deleted {message.text} from whitelist")
        #except:
        #    await message.answer(f'{message.text} is not in the whitelist')

if __name__ == '__main__':
    print(123)
    dp.run_polling(bot)
