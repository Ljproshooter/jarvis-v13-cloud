-- LJ AI V15.9.6 two-way paired-device update.
-- Run once in Supabase SQL Editor before deploying the V15.9.6 cloud code.
-- Existing device links, commands and account data are preserved.

begin;

alter table public.device_remote_commands
    drop constraint if exists device_remote_commands_action_check;

alter table public.device_remote_commands
    add constraint device_remote_commands_action_check check (action in (
        'show_notification', 'media_play_pause', 'media_next', 'volume_mute',
        'lock_pc', 'open_lj_ai', 'run_diagnostic', 'open_app'
    ));

commit;
