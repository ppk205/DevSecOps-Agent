import { Request, Response } from "express";
export function go(req: Request, res: Response): void {
  res.redirect("/home");
}
