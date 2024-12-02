use termimad::{
    crossterm::style::Color::{Cyan, Green, Magenta, Yellow}, rgb, Alignment, MadSkin
};

pub fn init_skin() -> MadSkin {
    let mut skin = MadSkin::default();
    skin.set_headers_fg(rgb(255, 187, 0));
    skin.bold.set_fg(Yellow);
    skin.inline_code.set_fgbg(Cyan, rgb(40, 40, 60));
    skin.italic.set_fgbg(Green, rgb(30, 30, 40));
    skin.paragraph.align = Alignment::Center;
    skin.table.align = Alignment::Center;
    skin.table.set_fg(Magenta);
    skin
}
