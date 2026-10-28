import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { vTokenEndpointAuthMethod } from "./schema";

const { array, boolean, object, string } = v;

const vClient = object({
  clientId: string(),
  appId: string(),
  secretHash: string(),
  tokenEndpointAuthMethod: vTokenEndpointAuthMethod,
  redirectUri: string(),
});

/** Registers one deployment of an app as a client with its single exact redirect URI. */
export const create = mutation({
  args: {
    clientId: string(),
    appId: string(),
    secretHash: string(),
    tokenEndpointAuthMethod: vTokenEndpointAuthMethod,
    redirectUri: string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    // A registration that read its token before `apps.remove` ran must not leave a client behind:
    // a client exists only while its app does, so /authorize need not read the app.
    const app = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .unique();
    if (app === null) {
      throw new Error(`Unknown app "${args.appId}"`);
    }
    const existing = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (existing !== null) {
      throw new Error(`A client with id "${args.clientId}" already exists`);
    }
    await ctx.db.insert("clients", {
      clientId: args.clientId,
      appId: args.appId,
      secretHash: args.secretHash,
      tokenEndpointAuthMethod: args.tokenEndpointAuthMethod,
      redirectUri: args.redirectUri,
    });
    return null;
  },
});

export const get = query({
  args: { clientId: string() },
  returns: v.union(vClient, v.null()),
  handler: async (ctx, args) => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client === null) {
      return null;
    }
    const { _id, _creationTime, ...fields } = client;
    return fields;
  },
});

/** The clients of one app, oldest first. */
export const listByApp = query({
  args: { appId: string() },
  returns: array(vClient),
  handler: async (ctx, args) => {
    const clients = await ctx.db
      .query("clients")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .collect();
    return clients.map(({ _id, _creationTime, ...fields }) => fields);
  },
});

export const remove = mutation({
  args: { clientId: string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client !== null) {
      await ctx.db.delete("clients", client._id);
    }
    return null;
  },
});

/**
 * Deletes a client for `DELETE /register/<client_id>`, whose registration token names `appId`.
 * False when no client has this id or it belongs to another app: the endpoint answers both with
 * 404, so a token of one app learns nothing about the clients of another.
 */
export const unregister = mutation({
  args: { clientId: string(), appId: string() },
  returns: boolean(),
  handler: async (ctx, args) => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client === null || client.appId !== args.appId) {
      return false;
    }
    await ctx.db.delete("clients", client._id);
    return true;
  },
});
