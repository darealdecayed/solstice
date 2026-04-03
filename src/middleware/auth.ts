import { Request, Response, NextFunction } from 'express'

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'] as string
  const studentEmail = req.headers['x-student-email'] as string
  const license = req.headers['x-license'] as string

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' })
  }

  if (!/^[0-9]{10}$/.test(apiKey)) {
    return res.status(401).json({ error: 'Invalid API key format' })
  }

  if (!studentEmail) {
    return res.status(403).json({ error: 'Student email required' })
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(edu|k12\.[a-z]{2}\.us|dev)$/
  if (!emailRegex.test(studentEmail)) {
    return res.status(403).json({ error: 'Invalid student email format' })
  }

  if (!license) {
    return res.status(403).json({ error: 'License required' })
  }

  if (!/^[0-9]{10}$/.test(license)) {
    return res.status(403).json({ error: 'Invalid license format' })
  }

  ;(req as any).apiKey = apiKey
  ;(req as any).studentEmail = studentEmail
  ;(req as any).license = license

  next()
}
