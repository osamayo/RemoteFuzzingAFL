int main()
{

    
  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 use_stacking = 1 + rand_below(afl, stack_max);

    afl->stage_cur_val = use_stacking;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s HAVOC-%u-%u",
             afl->queue_cur->fname, afl->queue_cur->is_ascii, use_stacking);
#endif

    for (i = 0; i < use_stacking; ++i) {

      if (afl->custom_mutators_count) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (unlikely(el->stacked_custom &&
                       rand_below(afl, 100) < el->stacked_custom_prob)) {

            u8    *custom_havoc_buf = NULL;
            size_t new_len = el->afl_custom_havoc_mutation(
                el->data, out_buf, temp_len, &custom_havoc_buf, MAX_FILE);
            if (unlikely(!custom_havoc_buf)) {

              FATAL("Error in custom_havoc (return %zu)", new_len);

            }

            if (likely(new_len > 0 && custom_havoc_buf)) {

              temp_len = new_len;
              if (out_buf != custom_havoc_buf) {

                out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len);
                if (unlikely(!afl->out_buf)) { PFATAL("alloc"); }
                memcpy(out_buf, custom_havoc_buf, temp_len);

              }

            }

          }

        });

      }

    retry_havoc_step: {
      puts("Retry_havoc_step\n");
      u32 r = rand_below(afl, rand_max), item;

      switch (mutation_array[r]) {

        case MUT_FLIPBIT: {

          /* Flip a single bit somewhere. Spooky! */
          u8  bit = rand_below(afl, 8);
          u32 off = rand_below(afl, temp_len);
          out_buf[off] ^= 1 << bit;

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP-BIT_%u", bit);
          strcat(afl->mutation, afl->m_tmp);
#endif
          break;

        }

        case MUT_INTERESTING8: {

          /* Set byte to interesting value. */

          item = rand_below(afl, sizeof(interesting_8));
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] = interesting_8[item];
          break;

        }

        case MUT_INTERESTING16: {

          /* Set word to interesting value, little endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_16) >> 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
              interesting_16[item];

          break;

        }

        case MUT_INTERESTING16BE: {

          /* Set word to interesting value, big endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_16) >> 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
              SWAP16(interesting_16[item]);

          break;

        }

        case MUT_INTERESTING32: {

          /* Set dword to interesting value, little endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_32) >> 2);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
              interesting_32[item];

          break;

        }

        case MUT_INTERESTING32BE: {

          /* Set dword to interesting value, big endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_32) >> 2);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
              SWAP32(interesting_32[item]);

          break;

        }

        case MUT_ARITH8_: {

          /* Randomly subtract from byte. */

          item = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8-_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] -= item;
          break;

        }

        case MUT_ARITH8: {

          /* Randomly add to byte. */

          item = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8+_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] += item;
          break;

        }

        case MUT_ARITH16_: {

          /* Randomly subtract from word, little endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16-_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) -= item;

          break;

        }

        case MUT_ARITH16BE_: {

          /* Randomly subtract from word, big endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE-_%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

          break;

        }

        case MUT_ARITH16: {

          /* Randomly add to word, little endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) += item;

          break;

        }

        case MUT_ARITH16BE: {

          /* Randomly add to word, big endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE+__%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

          break;

        }

        case MUT_ARITH32_: {

          /* Randomly subtract from dword, little endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32-_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) -= item;

          break;

        }

        case MUT_ARITH32BE_: {

          /* Randomly subtract from dword, big endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE-_%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          break;

        }

        case MUT_ARITH32: {

          /* Randomly add to dword, little endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) += item;

          break;

        }

        case MUT_ARITH32BE: {

          /* Randomly add to dword, big endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE+_%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          break;

        }

        case MUT_RAND8: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          u32 pos = rand_below(afl, temp_len);
          item = 1 + rand_below(afl, 255);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8_%u",
                   out_buf[pos] ^ item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[pos] ^= item;
          break;

        }

        case MUT_CLONE_COPY: {

          if (likely(temp_len + HAVOC_BLK_XL < MAX_FILE)) {

            /* Clone bytes. */

            u32 clone_len = choose_block_len(afl, temp_len);
            u32 clone_from = rand_below(afl, temp_len - clone_len + 1);
            u32 clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s_%u_%u_%u",
                     "COPY", clone_from, clone_to, clone_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;

          } else if (unlikely(temp_len < 8)) {

            break;

          } else {

            goto retry_havoc_step;

          }

          break;

        }

        case MUT_CLONE_FIXED: {

          if (likely(temp_len + HAVOC_BLK_XL < MAX_FILE)) {

            /* Insert a block of constant bytes (25%). */

            u32 clone_len = choose_block_len(afl, HAVOC_BLK_XL);
            u32 clone_to = rand_below(afl, temp_len);
            u32 strat = rand_below(afl, 2);
            u32 clone_from = clone_to ? clone_to - 1 : 0;
            item = strat ? rand_below(afl, 256) : out_buf[clone_from];

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s_%u_%u_%u",
                     "FIXED", strat, clone_to, clone_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memset(new_buf + clone_to, item, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;

          } else if (unlikely(temp_len < 8)) {

            break;

          } else {

            goto retry_havoc_step;

          }

          break;

        }

        case MUT_OVERWRITE_COPY: {

          /* Overwrite bytes with a randomly selected chunk bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 copy_from, copy_to,
              copy_len = choose_block_len(afl, temp_len - 1);

          do {

            copy_from = rand_below(afl, temp_len - copy_len + 1);
            copy_to = rand_below(afl, temp_len - copy_len + 1);

          } while (unlikely(copy_from == copy_to));

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " OVERWRITE-COPY_%u_%u_%u",
                   copy_from, copy_to, copy_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          break;

        }

        case MUT_OVERWRITE_FIXED: {

          /* Overwrite bytes with fixed bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 copy_len = choose_block_len(afl, temp_len - 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);
          u32 strat = rand_below(afl, 2);
          u32 copy_from = copy_to ? copy_to - 1 : 0;
          item = strat ? rand_below(afl, 256) : out_buf[copy_from];

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                   " OVERWRITE-FIXED_%u_%u_%u-%u", strat, item, copy_to,
                   copy_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memset(out_buf + copy_to, item, copy_len);

          break;

        }

        case MUT_BYTEADD: {

          /* Increase byte by 1. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " BYTEADD_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)]++;
          break;

        }

        case MUT_BYTESUB: {

          /* Decrease byte by 1. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " BYTESUB_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)]--;
          break;

        }

        case MUT_FLIP8: {

          /* Flip byte with a XOR 0xff. This is the same as NEG. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP8_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] ^= 0xff;
          break;

        }

        case MUT_SWITCH: {

          if (unlikely(temp_len < 4)) { break; }  // no retry

          /* Switch bytes. */

          u32 to_end, switch_to, switch_len, switch_from;
          switch_from = rand_below(afl, temp_len);
          do {

            switch_to = rand_below(afl, temp_len);

          } while (unlikely(switch_from == switch_to));

          if (switch_from < switch_to) {

            switch_len = switch_to - switch_from;
            to_end = temp_len - switch_to;

          } else {

            switch_len = switch_from - switch_to;
            to_end = temp_len - switch_from;

          }

          switch_len = choose_block_len(afl, MIN(switch_len, to_end));

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SWITCH-%s_%u_%u_%u",
                   "switch", switch_from, switch_to, switch_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), switch_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

          /* Backup */

          memcpy(new_buf, out_buf + switch_from, switch_len);

          /* Switch 1 */

          memcpy(out_buf + switch_from, out_buf + switch_to, switch_len);

          /* Switch 2 */

          memcpy(out_buf + switch_to, new_buf, switch_len);

          break;

        }

        case MUT_DEL: {

          /* Delete bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          /* Don't delete too much. */

          u32 del_len = choose_block_len(afl, temp_len - 1);
          u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL_%u_%u", del_from,
                   del_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          break;

        }

        case MUT_SHUFFLE: {

          /* Shuffle bytes. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 len = choose_block_len(afl, temp_len - 1);
          u32 off = rand_below(afl, temp_len - len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SHUFFLE_%u", len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          for (u32 i = len - 1; i > 0; i--) {

            u32 j;
            do {

              j = rand_below(afl, i + 1);

            } while (unlikely(i == j));

            unsigned char temp = out_buf[off + i];
            out_buf[off + i] = out_buf[off + j];
            out_buf[off + j] = temp;

          }

          break;

        }

        case MUT_DELONE: {

          /* Delete bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          /* Don't delete too much. */

          u32 del_len = 1;
          u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DELONE_%u", del_from);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          break;

        }

        case MUT_INSERTONE: {

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 clone_len = 1;
          u32 clone_to = rand_below(afl, temp_len);
          u32 strat = rand_below(afl, 2);
          u32 clone_from = clone_to ? clone_to - 1 : 0;
          item = strat ? rand_below(afl, 256) : out_buf[clone_from];

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INSERTONE_%u_%u", strat,
                   clone_to);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u8 *new_buf =
              afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

          /* Head */

          memcpy(new_buf, out_buf, clone_to);

          /* Inserted part */

          memset(new_buf + clone_to, item, clone_len);

          /* Tail */
          memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                 temp_len - clone_to);

          out_buf = new_buf;
          afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
          temp_len += clone_len;

          break;

        }

        case MUT_ASCIINUM: {

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 off = rand_below(afl, temp_len), off2 = off, cnt = 0;

          while (off2 + cnt < temp_len && !isdigit(out_buf[off2 + cnt])) {

            ++cnt;

          }

          // none found, wrap
          if (off2 + cnt == temp_len) {

            off2 = 0;
            cnt = 0;

            while (cnt < off && !isdigit(out_buf[off2 + cnt])) {

              ++cnt;

            }

            if (cnt == off) {

              if (temp_len < 8) {

                break;

              } else {

                goto retry_havoc_step;

              }

            }

          }

          off = off2 + cnt;
          off2 = off + 1;

          while (off2 < temp_len && isdigit(out_buf[off2])) {

            ++off2;

          }

          s64 val = out_buf[off] - '0';
          for (u32 i = off + 1; i < off2; ++i) {

            val = (val * 10) + out_buf[i] - '0';

          }

          if (off && out_buf[off - 1] == '-') { val = -val; }

          u32 strat = rand_below(afl, 8);
          switch (strat) {

            case 0:
              val++;
              break;
            case 1:
              val--;
              break;
            case 2:
              val *= 2;
              break;
            case 3:
              val /= 2;
              break;
            case 4:
              if (likely(val && (u64)val < 0x19999999)) {

                val = (u64)rand_next(afl) % (u64)((u64)val * 10);

              } else {

                val = rand_below(afl, 256);

              }

              break;
            case 5:
              val += rand_below(afl, 256);
              break;
            case 6:
              val -= rand_below(afl, 256);
              break;
            case 7:
              val = ~(val);
              break;

          }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ASCIINUM_%u_%u_%u",
                   afl->queue_cur->is_ascii, strat, off);
          strcat(afl->mutation, afl->m_tmp);
#endif
          // fprintf(stderr, "val: %u-%u = %ld\n", off, off2, val);

          char buf[20];
          snprintf(buf, sizeof(buf), "%" PRId64, val);

          // fprintf(stderr, "BEFORE: %s\n", out_buf);

          u32 old_len = off2 - off;
          u32 new_len = strlen(buf);

          if (old_len == new_len) {

            memcpy(out_buf + off, buf, new_len);

          } else {

            u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                      temp_len + new_len - old_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, off);

            /* Inserted part */

            memcpy(new_buf + off, buf, new_len);

            /* Tail */
            memcpy(new_buf + off + new_len, out_buf + off2, temp_len - off2);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += (new_len - old_len);

          }

          // fprintf(stderr, "AFTER : %s\n", out_buf);
          break;

        }

        case MUT_INSERTASCIINUM: {

          u32 len = 1 + rand_below(afl, 8);
          u32 pos = rand_below(afl, temp_len);
          /* Insert ascii number. */
          if (unlikely(temp_len < pos + len)) {

            if (unlikely(temp_len < 8)) {

              break;

            } else {

              goto retry_havoc_step;

            }

          }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INSERTASCIINUM_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          u64  val = rand_next(afl);
          char buf[20];
          snprintf(buf, sizeof(buf), "%llu", val);
          memcpy(out_buf + pos, buf, len);

          break;

        }

        case MUT_EXTRA_OVERWRITE: {

          if (unlikely(!afl->extras_cnt)) { goto retry_havoc_step; }

          /* Use the dictionary. */

          u32 use_extra = rand_below(afl, afl->extras_cnt);
          u32 extra_len = afl->extras[use_extra].len;

          if (unlikely(extra_len > temp_len)) { goto retry_havoc_step; }

          u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA-OVERWRITE_%u_%u",
                   insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memcpy(out_buf + insert_at, afl->extras[use_extra].data, extra_len);

          break;

        }

        case MUT_EXTRA_INSERT: {

          if (unlikely(!afl->extras_cnt)) { goto retry_havoc_step; }

          u32 use_extra = rand_below(afl, afl->extras_cnt);
          u32 extra_len = afl->extras[use_extra].len;
          if (unlikely(temp_len + extra_len >= MAX_FILE)) {

            goto retry_havoc_step;

          }

          u8 *ptr = afl->extras[use_extra].data;
          u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA-INSERT_%u_%u",
                   insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
          if (unlikely(!out_buf)) { PFATAL("alloc"); }

          /* Tail */
          memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                  temp_len - insert_at);

          /* Inserted part */
          memcpy(out_buf + insert_at, ptr, extra_len);
          temp_len += extra_len;

          break;

        }

        case MUT_AUTO_EXTRA_OVERWRITE: {

          if (unlikely(!afl->a_extras_cnt)) { goto retry_havoc_step; }

          /* Use the dictionary. */

          u32 use_extra = rand_below(afl, afl->a_extras_cnt);
          u32 extra_len = afl->a_extras[use_extra].len;

          if (unlikely(extra_len > temp_len)) { goto retry_havoc_step; }

          u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                   " AUTO-EXTRA-OVERWRITE_%u_%u", insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memcpy(out_buf + insert_at, afl->a_extras[use_extra].data, extra_len);

          break;

        }

        case MUT_AUTO_EXTRA_INSERT: {

          if (unlikely(!afl->a_extras_cnt)) { goto retry_havoc_step; }

          u32 use_extra = rand_below(afl, afl->a_extras_cnt);
          u32 extra_len = afl->a_extras[use_extra].len;
          if (unlikely(temp_len + extra_len >= MAX_FILE)) {

            goto retry_havoc_step;

          }

          u8 *ptr = afl->a_extras[use_extra].data;
          u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " AUTO-EXTRA-INSERT_%u_%u",
                   insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
          if (unlikely(!out_buf)) { PFATAL("alloc"); }

          /* Tail */
          memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                  temp_len - insert_at);

          /* Inserted part */
          memcpy(out_buf + insert_at, ptr, extra_len);
          temp_len += extra_len;

          break;

        }

        case MUT_SPLICE_OVERWRITE: {

          if (unlikely(afl->ready_for_splicing_count <= 1)) {

            goto retry_havoc_step;

          }

          /* Pick a random queue entry and seek to it. */

          u32 tid;
          do {

            tid = rand_below(afl, afl->queued_items);

          } while (unlikely(tid == afl->current_entry ||

                            afl->queue_buf[tid]->len < 4));

          /* Get the testcase for splicing. */
          struct queue_entry *target = afl->queue_buf[tid];
          u32                 new_len = target->len;
          u8                 *new_buf = queue_testcase_get(afl, target);

          /* overwrite mode */

          u32 copy_from, copy_to, copy_len;

          copy_len = choose_block_len(afl, new_len - 1);
          if (copy_len > temp_len) copy_len = temp_len;

          copy_from = rand_below(afl, new_len - copy_len + 1);
          copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                   " SPLICE-OVERWRITE_%u_%u_%u_%s", copy_from, copy_to,
                   copy_len, target->fname);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

          break;

        }

        case MUT_SPLICE_INSERT: {

          if (unlikely(afl->ready_for_splicing_count <= 1)) {

            goto retry_havoc_step;

          }

          if (unlikely(temp_len + HAVOC_BLK_XL >= MAX_FILE)) {

            goto retry_havoc_step;

          }

          /* Pick a random queue entry and seek to it. */

          u32 tid;
          do {

            tid = rand_below(afl, afl->queued_items);

          } while (unlikely(tid == afl->current_entry ||

                            afl->queue_buf[tid]->len < 4));

          /* Get the testcase for splicing. */
          struct queue_entry *target = afl->queue_buf[tid];
          u32                 new_len = target->len;
          u8                 *new_buf = queue_testcase_get(afl, target);

          /* insert mode */

          u32 clone_from, clone_to, clone_len;

          clone_len = choose_block_len(afl, new_len);
          clone_from = rand_below(afl, new_len - clone_len + 1);
          clone_to = rand_below(afl, temp_len + 1);

          u8 *temp_buf =
              afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len + 1);
          if (unlikely(!temp_buf)) { PFATAL("alloc"); }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SPLICE-INSERT_%u_%u_%u_%s",
                   clone_from, clone_to, clone_len, target->fname);
          strcat(afl->mutation, afl->m_tmp);
#endif
          /* Head */

          memcpy(temp_buf, out_buf, clone_to);

          /* Inserted part */

          memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

          /* Tail */
          memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                 temp_len - clone_to);

          out_buf = temp_buf;
          afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
          temp_len += clone_len;

          break;

        }

      }

    }

    }

    if (common_fuzz_stuff(afl, out_buf, temp_len)) { goto abandon_entry; }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (afl->queued_items != havoc_queued) {

      if (perf_score <= afl->havoc_max_mult * 100) {

        afl->stage_max *= 2;
        perf_score *= 2;

      }

      havoc_queued = afl->queued_items;

    }

  }

}