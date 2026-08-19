import { defineCollection } from "astro:content";

export const collections = {
  posts: defineCollection({}),
  pages: defineCollection({}),
};
