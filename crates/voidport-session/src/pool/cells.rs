//! A place leads to its cell, and each list to its next cell, so no step
//! searches the storage. A list that leads to a cell of another kind is
//! reported as [`InvariantError`].

use core::marker::PhantomData;

use crate::table::{AllocationRefused, InvariantError};

#[derive(Debug)]
pub struct Cell<C> {
    content: Content<C>,
}

impl<C> Cell<C> {
    #[must_use]
    pub const fn vacant() -> Self {
        Self {
            content: Content::Vacant { next: None },
        }
    }
}

impl<C> Default for Cell<C> {
    fn default() -> Self {
        Self::vacant()
    }
}

/// Both accessors expose the same cells. Their number changes only through a
/// successful [`Cells::grow`], and the cells a pool starts with are vacant.
pub trait Cells<C> {
    fn cells(&self) -> &[Cell<C>];
    fn cells_mut(&mut self) -> &mut [Cell<C>];
    fn grow(&mut self, len: usize) -> Result<(), AllocationRefused>;
}

#[derive(Debug)]
pub(super) enum Content<C> {
    /// Nothing. `next` is the cell vacated before this one, while this one is
    /// among the vacated cells.
    Vacant { next: Option<usize> },
    Open {
        id: u64,
        stamp: Stamp,
        connection: C,
        role: Role,
    },
    Settling {
        id: u64,
        stamp: Stamp,
        outstanding: Outstanding,
    },
}

/// A place whose connection has left, or whose cell another connection took
/// since, refers to no connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub(super) index: usize,
    pub(super) stamp: Stamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stamp(pub(super) u64);

#[derive(Debug, PartialEq, Eq)]
pub struct Open<'a, C> {
    pub place: Place,
    pub connection: &'a C,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// Idle, between the idle connection given back after it (`above`) and
    /// the one given back before it (`below`).
    Idle {
        above: Option<usize>,
        below: Option<usize>,
    },
    Busy,
    Resting,
    Subscribed,
    Leaving,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outstanding {
    Request,
    Forgets,
    Both,
}

impl Outstanding {
    pub(super) fn of(role: Role, forgets: usize) -> Option<Self> {
        match (role == Role::Busy, forgets != 0) {
            (true, true) => Some(Self::Both),
            (true, false) => Some(Self::Request),
            (false, true) => Some(Self::Forgets),
            (false, false) => None,
        }
    }

    pub(super) fn without(self, settled: Self) -> Option<Self> {
        match (self, settled) {
            (Self::Both, Self::Request) => Some(Self::Forgets),
            (Self::Both, Self::Forgets) => Some(Self::Request),
            (Self::Request, Self::Request) | (Self::Forgets, Self::Forgets) | (_, Self::Both) => {
                None
            }
            (outstanding, _) => Some(outstanding),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Unplaced {
    Refused,
    Broken,
}

#[derive(Debug)]
pub(super) struct Storage<C, S> {
    cells: S,
    vacated: Option<usize>,
    /// The first cell no connection was put in yet. Every cell from it on is
    /// vacant and in no list.
    fresh: usize,
    stamp: u64,
    connection: PhantomData<C>,
}

impl<C, S: Cells<C>> Storage<C, S> {
    pub(super) fn new(cells: S) -> Self {
        Self {
            cells,
            vacated: None,
            fresh: 0,
            stamp: 0,
            connection: PhantomData,
        }
    }

    pub(super) fn put(&mut self, id: u64, connection: C, role: Role) -> Result<Place, Unplaced> {
        let index = match self.vacated {
            Some(vacated) => vacated,
            None => {
                let len = self.cells.cells().len();
                if self.fresh == len {
                    let grown = len.checked_add(1).ok_or(Unplaced::Refused)?;
                    self.cells
                        .grow(grown)
                        .map_err(|AllocationRefused| Unplaced::Refused)?;
                }
                self.fresh
            }
        };
        let stamp = Stamp(self.stamp);
        let content = self.content_mut(index).ok_or(Unplaced::Broken)?;
        let Content::Vacant { next } = *content else {
            return Err(Unplaced::Broken);
        };
        *content = Content::Open {
            id,
            stamp,
            connection,
            role,
        };
        self.stamp = self.stamp.wrapping_add(1);
        if self.vacated.is_some() {
            self.vacated = next;
        } else {
            self.fresh += 1;
        }
        Ok(Place { index, stamp })
    }

    pub(super) fn vacate(&mut self, index: usize) -> Result<(), InvariantError> {
        let next = self.vacated;
        *self.content_mut(index).ok_or(InvariantError)? = Content::Vacant { next };
        self.vacated = Some(index);
        Ok(())
    }

    pub(super) fn content(&self, index: usize) -> Option<&Content<C>> {
        Some(&self.cells.cells().get(index)?.content)
    }

    pub(super) fn content_mut(&mut self, index: usize) -> Option<&mut Content<C>> {
        Some(&mut self.cells.cells_mut().get_mut(index)?.content)
    }

    /// The position `place` refers to, while the connection put there when
    /// the place was handed out is still there, open or being settled.
    pub(super) fn index(&self, place: Place) -> Option<usize> {
        let stamp = match self.content(place.index)? {
            Content::Open { stamp, .. } | Content::Settling { stamp, .. } => *stamp,
            Content::Vacant { .. } => return None,
        };
        (stamp == place.stamp).then_some(place.index)
    }

    pub(super) fn open(&self, index: usize) -> Option<Open<'_, C>> {
        match self.content(index)? {
            Content::Open {
                stamp, connection, ..
            } => Some(Open {
                place: Place {
                    index,
                    stamp: *stamp,
                },
                connection,
            }),
            Content::Vacant { .. } | Content::Settling { .. } => None,
        }
    }

    pub(super) fn take_open(&mut self, next: &mut usize) -> Option<C> {
        while let Some(cell) = self.cells.cells_mut().get_mut(*next) {
            *next += 1;
            match core::mem::replace(&mut cell.content, Content::Vacant { next: None }) {
                Content::Open { connection, .. } => return Some(connection),
                other => cell.content = other,
            }
        }
        None
    }

    fn role_mut(&mut self, index: usize) -> Result<&mut Role, InvariantError> {
        match self.content_mut(index) {
            Some(Content::Open { role, .. }) => Ok(role),
            _ => Err(InvariantError),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct Idle {
    pub(super) top: Option<usize>,
}

impl Idle {
    pub(super) fn only(index: usize) -> Self {
        Self { top: Some(index) }
    }

    pub(super) fn push<C, S: Cells<C>>(
        &mut self,
        storage: &mut Storage<C, S>,
        index: usize,
    ) -> Result<(), InvariantError> {
        let below = self.top;
        if let Some(below) = below {
            set_above(storage, below, Some(index))?;
        }
        *storage.role_mut(index)? = Role::Idle { above: None, below };
        self.top = Some(index);
        Ok(())
    }

    pub(super) fn pop<C, S: Cells<C>>(
        &mut self,
        storage: &mut Storage<C, S>,
    ) -> Result<Option<usize>, InvariantError> {
        let Some(top) = self.top else {
            return Ok(None);
        };
        let role = storage.role_mut(top)?;
        let Role::Idle { above: None, below } = *role else {
            return Err(InvariantError);
        };
        *role = Role::Busy;
        self.unlink(storage, top, None, below)?;
        Ok(Some(top))
    }

    pub(super) fn unlink<C, S: Cells<C>>(
        &mut self,
        storage: &mut Storage<C, S>,
        index: usize,
        above: Option<usize>,
        below: Option<usize>,
    ) -> Result<(), InvariantError> {
        match above {
            Some(above) => set_below(storage, above, below)?,
            None if self.top == Some(index) => self.top = below,
            None => return Err(InvariantError),
        }
        if let Some(below) = below {
            set_above(storage, below, above)?;
        }
        Ok(())
    }
}

fn set_above<C, S: Cells<C>>(
    storage: &mut Storage<C, S>,
    index: usize,
    to: Option<usize>,
) -> Result<(), InvariantError> {
    let Role::Idle { above, .. } = storage.role_mut(index)? else {
        return Err(InvariantError);
    };
    *above = to;
    Ok(())
}

fn set_below<C, S: Cells<C>>(
    storage: &mut Storage<C, S>,
    index: usize,
    to: Option<usize>,
) -> Result<(), InvariantError> {
    let Role::Idle { below, .. } = storage.role_mut(index)? else {
        return Err(InvariantError);
    };
    *below = to;
    Ok(())
}
