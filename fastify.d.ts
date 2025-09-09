// We manually type FastifyRequest and FastifyReply to avoid adding fastify as a dependency, which makes it hard for the
// hook to work in both Fastify v2 and v3 projects.
//
// This is the bare minimum we need from those types to make the hook work and be properly typed.

type FastifyRequest = {
  query: unknown;
};

type FastifyReply = {
  code: (statusCode: number) => FastifyReply;
  send: (body?: unknown) => void;
};

type HookHandlerDoneFunction = <TError extends Error>(err?: TError) => void