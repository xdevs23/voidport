use voidport_session::table::AllocationRefused;

/// `cells` is left as it was when the memory is refused.
pub(super) fn grow_vacant<T>(
    cells: &mut Vec<T>,
    len: usize,
    vacant: impl FnMut() -> T,
) -> Result<(), AllocationRefused> {
    let Some(more) = len.checked_sub(cells.len()) else {
        return Ok(());
    };
    cells.try_reserve(more).map_err(|_| AllocationRefused)?;
    cells.resize_with(len, vacant);
    Ok(())
}
