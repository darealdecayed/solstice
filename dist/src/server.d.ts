declare global {
    namespace Express {
        interface Request {
            startTime?: number;
        }
    }
}
declare const app: import("express-serve-static-core").Express;
export default app;
//# sourceMappingURL=server.d.ts.map