import express from "express"
import cors from "cors"
import multer from "multer"
import dotenv from "dotenv"
import mysql from "mysql2/promise"
import { AccessParser } from "@regrapes/access-db-parser"
import fs from "fs/promises"
import path from "path"
import os from "os"
import crypto from "crypto"

dotenv.config()

const app = express()
const PORT = Number(process.env.PORT || 8080)

const MAX_ACCESS_MB = Number(process.env.MAX_ACCESS_MB || 100)
const MAX_ROWS = Number(process.env.MAX_ROWS || 5000)
const DEFAULT_PAGE_SIZE = Math.min(Number(process.env.DEFAULT_PAGE_SIZE || 100), MAX_ROWS)

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "https://mronlinestores.com,https://musrh.github.io")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean)

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
      return callback(null, true)
    }
    return callback(new Error("Origin non autorisée"))
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}))

app.use(express.json({ limit: "1mb" }))

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_ACCESS_MB * 1024 * 1024,
    files: 1,
  },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase()
    if (![".mdb", ".accdb"].includes(ext)) {
      return cb(new Error("Seuls les fichiers .mdb et .accdb sont acceptés."))
    }
    cb(null, true)
  },
})

/*
 * Les fichiers Access sont gardés uniquement en mémoire.
 * Le serveur ne les enregistre donc pas sur disque.
 *
 * Un identifiant temporaire permet au frontend de demander ensuite
 * la liste des tables puis les lignes d'une table.
 */
const accessSessions = new Map()
const ACCESS_SESSION_TTL = Number(process.env.ACCESS_SESSION_TTL_MS || 15 * 60 * 1000)

function makeId() {
  return crypto.randomBytes(18).toString("hex")
}

function cleanupAccessSessions() {
  const now = Date.now()
  for (const [id, session] of accessSessions) {
    if (session.expiresAt <= now) accessSessions.delete(id)
  }
}

setInterval(cleanupAccessSessions, 60_000).unref()

function jsonSafe(value) {
  if (value === undefined) return null
  if (value instanceof Date) return value.toISOString()
  if (Buffer.isBuffer(value)) return value.toString("base64")
  if (typeof value === "bigint") return value.toString()
  if (typeof value === "object" && value !== null) {
    if (Array.isArray(value)) return value.map(jsonSafe)
    const out = {}
    for (const [k, v] of Object.entries(value)) out[k] = jsonSafe(v)
    return out
  }
  return value
}

function normalizeRows(rows) {
  return rows.map(row => {
    if (row && typeof row === "object" && !Array.isArray(row)) {
      return Object.fromEntries(Object.entries(row).map(([k, v]) => [k, jsonSafe(v)]))
    }
    return { value: jsonSafe(row) }
  })
}

function paginate(rows, page = 1, pageSize = DEFAULT_PAGE_SIZE) {
  const safePage = Math.max(1, Number(page) || 1)
  const safeSize = Math.min(MAX_ROWS, Math.max(1, Number(pageSize) || DEFAULT_PAGE_SIZE))
  const start = (safePage - 1) * safeSize
  const items = rows.slice(start, start + safeSize)

  return {
    rows: normalizeRows(items),
    page: safePage,
    pageSize: safeSize,
    totalRows: rows.length,
    totalPages: Math.max(1, Math.ceil(rows.length / safeSize)),
  }
}

// ============================================================
// HEALTH
// ============================================================

app.get("/", (req, res) => {
  res.json({
    status: "OK",
    service: "SaasBuilder Data Server",
    access: "MDB / ACCDB",
    mysql: true,
    maxAccessFileMB: MAX_ACCESS_MB,
    maxRowsPerResponse: MAX_ROWS,
    endpoints: [
      "POST /api/access/upload",
      "GET  /api/access/:sessionId/tables",
      "GET  /api/access/:sessionId/table/:table",
      "POST /api/mysql/test",
      "POST /api/mysql/tables",
      "POST /api/mysql/table",
    ],
  })
})

// ============================================================
// ACCESS
// ============================================================

app.post("/api/access/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Fichier Access manquant." })
    }

    const parser = new AccessParser(req.file.buffer)
    const tables = parser.getTables()

    const sessionId = makeId()

    accessSessions.set(sessionId, {
      parser,
      filename: req.file.originalname,
      createdAt: Date.now(),
      expiresAt: Date.now() + ACCESS_SESSION_TTL,
      tables,
    })

    res.json({
      success: true,
      sessionId,
      filename: req.file.originalname,
      tables,
      expiresInMs: ACCESS_SESSION_TTL,
    })
  } catch (error) {
    console.error("[ACCESS] upload:", error)
    res.status(400).json({
      error: "Impossible de lire cette base Access.",
      details: error.message,
    })
  }
})

app.get("/api/access/:sessionId/tables", (req, res) => {
  const session = accessSessions.get(req.params.sessionId)

  if (!session || session.expiresAt <= Date.now()) {
    accessSessions.delete(req.params.sessionId)
    return res.status(404).json({ error: "Session Access expirée ou introuvable." })
  }

  res.json({
    success: true,
    filename: session.filename,
    tables: session.tables,
    expiresAt: session.expiresAt,
  })
})

app.get("/api/access/:sessionId/table/:table", (req, res) => {
  const session = accessSessions.get(req.params.sessionId)

  if (!session || session.expiresAt <= Date.now()) {
    accessSessions.delete(req.params.sessionId)
    return res.status(404).json({ error: "Session Access expirée ou introuvable." })
  }

  const tableName = req.params.table

  if (!session.tables.includes(tableName)) {
    return res.status(404).json({ error: "Table Access introuvable." })
  }

  try {
    const table = session.parser.parseTable(tableName)

    /*
     * @regrapes/access-db-parser 2.x renvoie généralement :
     *   [{ data: { Colonne: valeur, ... }, rowNumber: 1 }, ...]
     * Certaines anciennes versions renvoient :
     *   { fields: [...], lines: [[...], [...]] }
     * On accepte les deux formats afin que les tables soient réellement
     * affichables quelle que soit la version du parseur.
     */
    let fields = []
    let allRows = []

    if (Array.isArray(table)) {
      allRows = table.map(item => {
        const data = item?.data && typeof item.data === "object"
          ? item.data
          : (item && typeof item === "object" ? item : {})
        return Object.fromEntries(
          Object.entries(data).map(([key, value]) => [key, jsonSafe(value)])
        )
      })
      fields = [...new Set(allRows.flatMap(row => Object.keys(row)))]
      allRows = allRows.map(row =>
        Object.fromEntries(fields.map(field => [field, row[field] ?? null]))
      )
    } else {
      fields = Array.isArray(table?.fields) ? table.fields : []
      const lines = Array.isArray(table?.lines) ? table.lines : []
      allRows = lines.map(line => {
        const row = {}
        fields.forEach((field, index) => {
          row[field] = jsonSafe(line?.[index])
        })
        return row
      })
    }

    const result = paginate(
      allRows,
      req.query.page,
      req.query.pageSize
    )

    res.json({
      success: true,
      source: "access",
      table: tableName,
      columns: fields,
      ...result,
    })
  } catch (error) {
    console.error("[ACCESS] table:", error)
    res.status(400).json({
      error: "Impossible de lire cette table Access.",
      details: error.message,
    })
  }
})

// ============================================================
// MYSQL
// ============================================================

function mysqlConfig(body) {
  return {
    host: body.host,
    port: Number(body.port || 3306),
    user: body.user,
    password: body.password,
    database: body.database,
    connectTimeout: Number(process.env.MYSQL_CONNECT_TIMEOUT || 10000),
    enableKeepAlive: true,
  }
}

function validateMysqlConfig(body) {
  for (const key of ["host", "user", "database"]) {
    if (!body?.[key] || typeof body[key] !== "string") {
      return `Champ MySQL manquant : ${key}`
    }
  }

  if (body.password !== undefined && typeof body.password !== "string") {
    return "Mot de passe MySQL invalide."
  }

  return null
}

app.post("/api/mysql/test", async (req, res) => {
  const validation = validateMysqlConfig(req.body)
  if (validation) return res.status(400).json({ error: validation })

  let connection

  try {
    connection = await mysql.createConnection(mysqlConfig(req.body))
    const [rows] = await connection.query("SELECT 1 AS connected")

    res.json({
      success: true,
      connected: true,
      result: rows[0]?.connected === 1,
      server: req.body.host,
      database: req.body.database,
    })
  } catch (error) {
    console.error("[MYSQL] test:", error)
    res.status(400).json({
      success: false,
      connected: false,
      error: "Connexion MySQL impossible.",
      details: error.message,
    })
  } finally {
    if (connection) await connection.end().catch(() => {})
  }
})

app.post("/api/mysql/tables", async (req, res) => {
  const validation = validateMysqlConfig(req.body)
  if (validation) return res.status(400).json({ error: validation })

  let connection

  try {
    connection = await mysql.createConnection(mysqlConfig(req.body))

    const [rows] = await connection.query(`
      SELECT TABLE_NAME AS tableName
      FROM information_schema.tables
      WHERE table_schema = ?
        AND table_type = 'BASE TABLE'
      ORDER BY TABLE_NAME
    `, [req.body.database])

    res.json({
      success: true,
      database: req.body.database,
      tables: rows.map(r => r.tableName),
    })
  } catch (error) {
    console.error("[MYSQL] tables:", error)
    res.status(400).json({
      error: "Impossible de récupérer les tables MySQL.",
      details: error.message,
    })
  } finally {
    if (connection) await connection.end().catch(() => {})
  }
})

function validIdentifier(value) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    /^[A-Za-z0-9_$-]+$/.test(value)
}

app.post("/api/mysql/table", async (req, res) => {
  const validation = validateMysqlConfig(req.body)
  if (validation) return res.status(400).json({ error: validation })

  const { table } = req.body

  if (!validIdentifier(table)) {
    return res.status(400).json({
      error: "Nom de table MySQL invalide.",
    })
  }

  let connection

  try {
    connection = await mysql.createConnection(mysqlConfig(req.body))

    const [tableCheck] = await connection.query(`
      SELECT TABLE_NAME
      FROM information_schema.tables
      WHERE table_schema = ?
        AND table_name = ?
        AND table_type = 'BASE TABLE'
      LIMIT 1
    `, [req.body.database, table])

    if (!tableCheck.length) {
      return res.status(404).json({ error: "Table MySQL introuvable." })
    }

    const [columns] = await connection.query(`
      SELECT COLUMN_NAME AS columnName
      FROM information_schema.columns
      WHERE table_schema = ?
        AND table_name = ?
      ORDER BY ORDINAL_POSITION
    `, [req.body.database, table])

    const columnNames = columns.map(c => c.columnName)

    // Les identifiants sont validés avant d'être placés dans la requête.
    const escapedTable = "??"
    const [rows] = await connection.query(
      `SELECT * FROM ${escapedTable} LIMIT ? OFFSET ?`,
      [table, Math.min(MAX_ROWS, Number(req.body.pageSize || DEFAULT_PAGE_SIZE)), Math.max(0, ((Number(req.body.page || 1) - 1) * Number(req.body.pageSize || DEFAULT_PAGE_SIZE)))]
    )

    const [countRows] = await connection.query(
      `SELECT COUNT(*) AS totalRows FROM ${escapedTable}`,
      [table]
    )

    const totalRows = Number(countRows[0]?.totalRows || 0)
    const page = Math.max(1, Number(req.body.page) || 1)
    const pageSize = Math.min(MAX_ROWS, Math.max(1, Number(req.body.pageSize) || DEFAULT_PAGE_SIZE))

    res.json({
      success: true,
      source: "mysql",
      database: req.body.database,
      table,
      columns: columnNames,
      rows: normalizeRows(rows),
      page,
      pageSize,
      totalRows,
      totalPages: Math.max(1, Math.ceil(totalRows / pageSize)),
    })
  } catch (error) {
    console.error("[MYSQL] table:", error)
    res.status(400).json({
      error: "Impossible de lire cette table MySQL.",
      details: error.message,
    })
  } finally {
    if (connection) await connection.end().catch(() => {})
  }
})

// ============================================================
// ERREURS
// ============================================================

app.use((err, req, res, next) => {
  console.error("[SERVER]", err)

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: `Fichier trop volumineux. Maximum : ${MAX_ACCESS_MB} Mo.`,
      })
    }
    return res.status(400).json({ error: err.message })
  }

  res.status(400).json({ error: err.message || "Erreur serveur." })
})

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 SaasBuilder Data Server sur le port ${PORT}`)
  console.log(`📁 Access : .mdb / .accdb`)
  console.log(`🐬 MySQL  : connexion distante`)
  console.log(`📦 Taille Access max : ${MAX_ACCESS_MB} Mo`)
})
