import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  Client,
  Collection,
  Events,
  GatewayIntentBits,
  InteractionContextType,
  MessageFlags,
  PermissionsBitField,
  Routes,
  SlashCommandBuilder,
} from "discord.js";
import "dotenv/config";
import { z } from "zod";
import { Elysia, file, status } from "elysia";
import { staticPlugin } from "@elysiajs/static";
import { verify } from "hcaptcha"

export const VerificationMetadataSchema = z.object({
  payloadVersionType: z.union([z.literal(1), z.literal(2)]),
  payloadVersion: z.number().int().min(0).max(9),
  payloadVersionSeed: z.number().int().min(0).max(999_999),
  tokenKey: z.string().min(1),
});

function base64ToUint8Array(base64: string) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export const VerificationCodeSchema = z.object({
  code: z.string().min(1),
  userId: z.string().min(1),
  metadata: VerificationMetadataSchema,
});

const client = new Client({
  intents: [
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.Guilds,
  ],
});

const cache = new Collection<string, string>()
const cacheExpired = new Collection<string, {
  createdAt: number,
  expiredAt: number
}>()

setInterval(() => {
  cacheExpired.forEach((value, key) => {
    if (value.expiredAt < (Date.now() / 1000)) {
      cache.delete(key)
      cacheExpired.delete(key)
    }
  })
}, 1000)

const app = new Elysia()
  .use(
    staticPlugin({
      indexHTML: true,
      assets: "./assets",
      prefix: "/assets",
    })
  )
  .get("/verify", () => file("./assets/index.html")).post('/api/verify', async ({ body, server, request }) => {
    const baseBody = z.object({
      _0: z.string(),
      _1: z.object({
        payloadVersionType: z.union([z.literal(1), z.literal(2)]),
        payloadVersion: z.number().int().min(0).max(9),
        payloadVersionSeed: z.number().int().min(0).max(999_999),
        tokenKey: z.string().min(1),
      }),
      _2: z.string(),
      _3: z.string(),
    })
    const data = baseBody.safeParse(body)
    if (!data.success) return status(401, { message: "คำขอไม่ถูกต้อง" })
    const { _0, _1, _2, _3 } = data.data
    const resultBodySchema = z.object({
      token: z.string(),
      ekey: z.string(),
      code: z.string(),
      confident: z.number(),
    })
    let resultBody: z.infer<typeof resultBodySchema> | null = null
    const code = await getVerificationCode(_2)
    if (!code) return status(401, { message: "คำขอไม่ถูกต้อง" })
    if (_1.payloadVersionType !== code.metadata.payloadVersionType || _1.payloadVersion !== code.metadata.payloadVersion || _1.payloadVersionSeed !== code.metadata.payloadVersionSeed || _1.tokenKey !== code.metadata.tokenKey) return status(401, { message: "คำขอไม่ถูกต้อง" })
    if (_1.payloadVersionType === 1) {
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        base64ToUint8Array(code.metadata.tokenKey),
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // 2. Convert encrypted Base64 back to Uint8Array
      const encryptedData = base64ToUint8Array(_0);

      // 3. Decrypt
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64ToUint8Array(code.metadata.tokenKey), // same IV used in encrypt
        },
        cryptoKey,
        encryptedData
      );
      const decryptedString = new TextDecoder().decode(decrypted);
      const r = resultBodySchema.safeParse(JSON.parse(decryptedString))
      if (!r.success) return status(401, { message: "คำขอไม่ถูกต้อง" })
      resultBody = r.data
    }
    if (!resultBody) return status(401, { message: "คำขอไม่ถูกต้อง" })
    if (code.code.replaceAll(" ", "+") != resultBody.code.replaceAll(" ", "+")) return status(401, { message: "คำขอไม่ถูกต้อง" })
    if (resultBody.confident < 0.5) return status(401, { message: "คำขอไม่ถูกต้อง" })
    const ip = server?.requestIP(request)
    if (!ip) return status(401, { message: "คำขอไม่ถูกต้อง" })
    const resultVerify = await verify(process.env.HCAPTCHA_SECRET_KEY!, resultBody.token, ip.address, process.env.HCAPTCHA_SITE_KEY!)
    if (!resultVerify.success) return status(401, { message: "คำขอไม่ถูกต้อง" })
    const guild = await client.guilds.fetch(process.env.GUILD_ID!)
    if (!guild) return status(401, { message: "คำขอไม่ถูกต้อง" })
    const member = await guild.members.fetch(code.userId)
    if (!member) return status(401, { message: "คำขอไม่ถูกต้อง" })
    await member.roles.add(process.env.ROLE_ID!)
    cache.delete(_2)
    cacheExpired.delete(_2)
    return {
      success: true,
      message: "ยืนยันตัวตนสำเร็จ"
    }
  }).head("/heartbeat", () => status(204));

const commands = [
  new SlashCommandBuilder()
    .setName("create_menu")
    .setDescription("Create a menu")
    .setContexts(InteractionContextType.Guild)
    .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator),
];

client.on(Events.ClientReady, async (client) => {
  console.log(`Logged in as ${client.user?.tag}!`);
  try {
    await client.rest.put(Routes.applicationCommands(client.application.id), {
      body: commands.map((e) => e.toJSON()),
    });
    console.log(`Created ${commands.length} commands`);
  } catch (error) {
    console.error(error);
  }
});

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  if (interaction.commandName === "create_menu") {
    await interaction.reply({
      embeds: [
        {
          description:
            "```\nกรุณาคลิกปุ่มด้านล่างเพื่อทำการยืนยันตัวตน\n```",
          color: 3311075,
          fields: [],
          author: {
            icon_url:
              "https://cdn.discordapp.com/avatars/1456313944191795263/200f830908f4fba171b9d089c47f974e.webp?size=128",
            name: "จำเป็นต้องยืนยันตัวตน",
          },
          image: {
            url: "https://i.pinimg.com/originals/ca/0f/0e/ca0f0ed42f907be80e8fd356400a9c96.gif",
          },
          footer: {
            text: "คุณจะถูกนำไปยังเว็บไซต์ภายนอก Discord เพื่อทำการยืนยันตัวตน",
          },
          timestamp: new Date().toISOString(),
        },
      ],
      components: [
        new ActionRowBuilder<ButtonBuilder>().addComponents(
          new ButtonBuilder()
            .setCustomId("verify")
            .setLabel("ยืนยันตัวตน")
            .setStyle(ButtonStyle.Primary)
            .setEmoji("🔒")
        ),
      ],
    });
  }
});

async function getVerificationCode(userId: string): Promise<z.infer<typeof VerificationCodeSchema> | null> {
  const code = cache.get(userId);
  if (!code) return null;
  return JSON.parse(code);
}

async function getOrCreateVerificationCode(
  userId: string
): Promise<z.infer<typeof VerificationCodeSchema>> {
  const code = cache.get(userId);
  if (!code) {
    const metadata = {
      payloadVersionType: 1,
      payloadVersion: Math.floor(Math.random() * 10),
      payloadVersionSeed: Math.floor(Math.random() * 1000000),
      tokenKey: crypto.getRandomValues(new Uint8Array(32)).toBase64(),
    } as z.infer<typeof VerificationMetadataSchema>;
    const newCode = crypto.getRandomValues(new Uint8Array(32)).toHex();
    cache.set(
      userId,
      JSON.stringify({
        code: newCode,
        userId: userId,
        metadata: metadata,
      })
    );
    cacheExpired.set(userId, {
      createdAt: Date.now() / 1000,
      expiredAt: (Date.now() / 1000) + 600,
    })
    return {
      code: newCode,
      userId: userId,
      metadata: metadata,
    };
  }
  return JSON.parse(code);
}

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  if (interaction.customId === "verify") {
    const code = await getOrCreateVerificationCode(interaction.user.id);
    await interaction.reply({
      flags: [MessageFlags.Ephemeral],
      embeds: [
        {
          description:
            "```\nกรุณากดปุ่ม \"ยืนยันตัวตน\" ด้านล่างเพื่อเปิดเว็บไซต์\n※ กรุณาทำการยืนยันตัวตนภายใน 10 นาที\n```",
          color: 3311075,
          fields: [],
          author: {
            icon_url:
              "https://cdn.discordapp.com/avatars/1456313944191795263/200f830908f4fba171b9d089c47f974e.webp?size=128",
            name: "กรุณาทำตามคำแนะนำด้านล่าง",
          },
          image: {
            url: "https://i.pinimg.com/originals/ca/0f/0e/ca0f0ed42f907be80e8fd356400a9c96.gif",
          },
          footer: {
            text: "※ เมื่อทำการยืนยันตัวตน เว็บไซต์ภายนอก Discord จะเปิดขึ้น และได้รับการปกป้องโดย hCaptcha",
          },
          timestamp: new Date().toISOString(),
        },
      ],
      components: [
        new ActionRowBuilder<ButtonBuilder>().addComponents(
          new ButtonBuilder()
            .setLabel("ยืนยันตัวตน")
            .setStyle(ButtonStyle.Link)
            .setURL(
              `${process.env.PUBLIC_URL}/verify?c=${code.code}&m=${Buffer.from(
                JSON.stringify({
                  metadata: code.metadata,
                  userId: code.userId,
                })
              ).toString("base64")}`
            )
        ),
      ],
    });
  }
});

client.login(process.env.BOT_TOKEN);
app.listen(3000, () => {
  console.log("Server started on port 3000");
});
